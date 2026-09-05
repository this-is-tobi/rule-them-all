// Package grant is consent for AI agents: which capabilities an MCP caller
// may invoke, on which records, until when.
//
// The safety class an operator opts into (`--allow-write`, an allowlist of
// destructive IDs) is a decision taken once, when the server is launched, for
// every call it will ever make. That is the coarse half. A grant is the fine
// half: it names one capability — optionally one record — carries a deadline,
// and can only be issued by a person at a terminal. An agent that could grant
// itself access would make the whole mechanism theatre, so the capabilities
// that issue grants refuse to run over MCP.
//
// This started as a kv-only feature, because a leaked password is the most
// obvious harm. It is not the only one: an agent that empties a task list or
// repoints /etc/hosts has also done something nobody asked for. So the gate
// lives here, next to the surface it defends, and is enforced once in the MCP
// bridge rather than by each plugin remembering to ask.
//
// The file is plaintext on purpose. It holds no secret — capability names,
// record names and timestamps — and it must be readable *without* unlocking
// anything, so "what is the agent allowed to do right now?" stays answerable
// in a hurry.
package grant

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/this-is-tobi/rta/internal/atomicfile"
	"github.com/this-is-tobi/rta/internal/config"
	"github.com/this-is-tobi/rta/internal/filelock"
	"github.com/this-is-tobi/rta/internal/paths"
	"github.com/this-is-tobi/rta/internal/policy"
	"github.com/this-is-tobi/rta/internal/seal"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

const (
	file = "grants.json"
	// DefaultTTL is short on purpose: a grant is for the task at hand.
	DefaultTTL = 15 * time.Minute
	// MaxTTL caps how long a grant can last. A day is already generous for
	// something whose entire point is that it expires.
	MaxTTL = 24 * time.Hour
)

// Grant authorizes one kind of call until it expires.
type Grant struct {
	// Target is a capability ID ("kv.get") or a plugin name ("kv"), which
	// covers every capability in it.
	Target string `json:"target"`
	// Scope narrows the grant to one record — the key, task or hostname the
	// capability names. Empty means every record the target can reach, which
	// is the wider and rarer thing to want.
	Scope string `json:"scope,omitempty"`
	// Profile narrows the grant to one of the operator's named connections.
	//
	// Empty means the call must name NO profile — the operator's base
	// configuration — and nothing else. **It is not a wildcard, and there is
	// no wildcard.**
	//
	// Scope's empty-means-every-record deliberately does not transfer. That is
	// a *record* wildcard inside a connection the operator already chose,
	// which is what makes it tolerable; a profile wildcard would be a
	// *connection* wildcard — one grant issued while pointed at a scratch
	// database authorizing the identical call against production. That is
	// the credential-redirect hole rebuilt from the grant side: the operator's
	// credential paired with a destination somebody else chose.
	//
	// It is also the only reading under which this field's arrival is safe for
	// grants already on disk: they unmarshal with Profile empty and keep
	// covering exactly the unprofiled calls they cover today, gaining nothing.
	// Under "empty means any" every one of them would silently widen to every
	// connection added afterwards.
	//
	// omitempty is load-bearing for the seal, not decoration. canonical() is
	// json.Marshal over the parsed []Grant, so a field that is the zero string
	// on every stored grant is omitted and re-encodes byte-identically, and
	// every existing seal still verifies. Without it old rows re-encode with
	// "profile":"", fail hmac.Equal, and rta reports its own file as forged.
	Profile string `json:"profile,omitempty"`
	// ProfilePin fingerprints the connection this grant was issued against:
	// profile.ConnStamp of the entry for this grant's namespace.
	//
	// **Because Profile is a name, and a name is not a connection.** Editing
	// an environment's `host`, `endpoint` or `secrets:` mapping repoints every
	// live grant naming it, silently: the operator consented to a call
	// reaching staging, and the identical grant now authorizes it against
	// whatever that name means afterwards. That became required the moment a
	// connection could also carry cluster coordinates and a credential read
	// out of that cluster.
	//
	// It is the same rule the rest of rta already follows for artifacts:
	// `--allow-destructive <id>@<digest>` and `plugins.<ns>@<digest>`
	// bind an authorization to a thing rather than to a label. This
	// binds it to a *connection* for the same reason and by the same means.
	//
	// **Required exactly when Profile is set.** An unprofiled grant keeps an
	// empty profile and an empty pin and is untouched, which is also what
	// leaves the field free for the seal. Both other readings are wrong:
	// "empty matches anything" rebuilds the hole for every grant issued before
	// this and makes the empty pin the default a blind-writing attacker
	// produces — the no-wildcard argument, one field along — and
	// "empty matches nothing" would refuse every live profiled grant on
	// upgrade. Fail-closed, self-healing within one TTL.
	//
	// Not re-stamped at load to smooth that upgrade, for legacy()'s own
	// reason: a migration that re-seals what it finds is the same hole with
	// more steps, because re-stamping binds the grant to whatever the config
	// says *now*, which is precisely the repoint this exists to catch.
	//
	// **What it can and cannot promise.** It is content-addressed, so it
	// answers "this differs from what was consented to" and not "this has been
	// edited since": a profile changed and changed back matches again. It
	// binds content and never provenance — Lookup's Trusted() check still
	// stands in front of it. And no hash over a config file can see
	// `RTA_PROFILE_<NAME>_<INPUT>`, so the claim is scoped to the configured
	// connection. See profile.ConnStamp.
	//
	// omitempty for the seal, exactly as Profile above documents: canonical()
	// is json.Marshal over the parsed []Grant, so a field that is the zero
	// string on every stored grant re-encodes byte-identically and every
	// existing seal still verifies.
	ProfilePin string `json:"profilePin,omitempty"`
	// Agent narrows the grant to one of the operator's named agents — the
	// name `rta mcp serve --as` was launched under.
	//
	// **Because consent is about a conversation, and rta could not tell two
	// of them apart.** Every MCP client on this machine reads the same grant
	// file, so a grant issued while talking to one agent authorized every
	// other one, including any installed afterwards, with nothing in the
	// record to say which had spent it. The operator who typed `rta grant
	// allow kv.get prod/db-password` was thinking of the agent in front of
	// them; what they got was every agent.
	//
	// Empty means the call must come from a server launched with NO name.
	// **It is not a wildcard, and there is no wildcard** — Profile's rule,
	// one field along, for Profile's reasons. Under "empty means any agent"
	// every grant already on disk would silently widen to cover each agent
	// added later, which is the hole this closes arriving from the other
	// side; and it would make the empty field the default a blind-writing
	// attacker produces. Under this reading they keep covering exactly the
	// unnamed calls they cover today and gain nothing.
	//
	// The cost is a real one and it is bounded: an operator who starts naming
	// their agents invalidates the grants they already hold, and re-consents
	// once. Fail-closed, self-healing within one TTL, because MaxTTL is a day.
	//
	// **What it is not is authentication.** The name is the operator's own
	// word, written where they wired the client up, and it is trusted exactly
	// as much as `--allow-write` beside it in the same argv. The name a client
	// asserts for *itself* over the wire is a different thing and never
	// reaches this field: a name a thing chooses for itself is not an
	// identity. See agentlog.Entry.Client, which records the claim as
	// provenance and never as authorization.
	//
	// omitempty is load-bearing for the seal, exactly as Profile documents:
	// canonical() is json.Marshal over the parsed []Grant, so a field that is
	// the zero string on every stored grant is omitted, re-encodes
	// byte-identically, and every existing seal still verifies.
	Agent   string    `json:"agent,omitempty"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	// From is where this grant was issued: a form, a terminal with somebody
	// at it, or a command with nobody there.
	//
	// **It is detection and not prevention, and the difference is the whole
	// point of the field.** An agent that can run commands can run `rta grant
	// allow` and issue itself anything — the seal stops a process that cannot
	// read the key from forging a line, and stops nothing that can simply ask
	// rta to write one. Nothing here changes that. What it changes is that
	// such a grant no longer looks identical to one the operator issued: a
	// row saying it arrived from a non-interactive command, minutes ago, is a
	// row somebody can recognise as not theirs.
	//
	// It can be defeated — a shell can allocate a pty and claim to be a
	// terminal — and it is worth having anyway, for the same reason the
	// record's hash chain is: against something running as you, making the
	// ordinary case visible is the most that is honest, and the ordinary case
	// is the one that actually happens.
	//
	// Empty on every grant sealed before this field existed, which is why the
	// vocabulary has no empty member: unknown and non-interactive are
	// different facts and a display that conflated them would accuse an old
	// grant of something.
	From string `json:"from,omitempty"`
	Note string `json:"note,omitempty"`
	// TTL is the window as the operator typed it ("15m", "1h"), so renew can
	// extend by the same amount rather than guess at one.
	//
	// Empty on every grant sealed before this field existed; renew falls back
	// to Expires.Sub(Issued), which for a grant that has never been renewed is
	// exactly the window it was issued with.
	TTL string `json:"ttl,omitempty"`
	// MaxUses caps how many successful calls this grant authorizes before it
	// is spent, on top of Expires. Zero means unlimited within the TTL — the
	// behavior of every grant issued before this field existed, and the
	// common case today: "for the next 15 minutes" needs no counting.
	MaxUses int `json:"maxUses,omitempty"`
	// Uses counts what has been spent so far. Reserve increments it *before*
	// the call runs, under the lock that authorized it, and hands back a
	// release() that gives the use back if the call then fails — a call
	// refused for an unrelated reason (the capability itself failed, the
	// process was killed mid-run) must not spend a one-time grant that
	// revealed nothing. Incrementing afterwards was the obvious ordering and
	// the wrong one: it left the decision and the spend in different critical
	// sections, so two concurrent calls both read Uses=0 and both ran.
	Uses int `json:"uses,omitempty"`
	// RateMax and RateWindow bound how *often* this grant may be spent:
	// "10 calls an hour" rather than "10 calls ever". Zero and empty mean no
	// rate limit, which is every grant issued before these fields existed.
	//
	// MaxUses answers "how much of this may happen at all" and a rate
	// answers "how fast", and the difference is what a leaked session turns
	// on. A MaxUses budget an agent can spend in one second is a budget that
	// buys the operator nothing: the whole point of a bound here is that a
	// session which has gone wrong degrades into something slow enough to be
	// noticed and stopped, rather than draining at machine speed. They
	// compose — a grant may carry both, and a call needs room under each.
	RateMax    int    `json:"rateMax,omitempty"`
	RateWindow string `json:"rateWindow,omitempty"`
	// Recent is when the uses inside the current window happened, oldest
	// first. Bounded by RateMax: a true rolling window rather than a
	// tumbling one, because a tumbling window lets twice the limit through
	// across a boundary and the storage a rolling one costs is exactly
	// proportional to the limit the operator chose.
	Recent []time.Time `json:"recent,omitempty"`
	// Server is the canonical URL of the machine this grant was issued FOR,
	// set exactly when a remote operator issued it and part of the signed
	// authority. It is what stops a fleet sharing one roster from becoming
	// one trust domain: without it, a signature made for staging would be
	// byte-for-byte valid on prod, and a same-uid agent on either machine
	// could transplant the row. guardcheck.go verifies it against the local
	// guard state's own bound URL, never against anything the row says.
	Server string `json:"server,omitempty"`
	// Sig is the guard's signature over this grant's authority fields —
	// present exactly when the operator passphrase guard was on at issuance,
	// see guardcheck.go for what it covers, what it leaves to the seal, and
	// the all-or-nothing rule loadAll applies to it.
	//
	// omitempty is load-bearing for the seal, exactly as Profile documents:
	// on every grant issued with the guard off the field is the zero string,
	// re-encodes byte-identically, and every existing seal still verifies.
	Sig string `json:"sig,omitempty"`
}

// MaxRate bounds what --rate will accept.
//
// Recent holds one timestamp per use in the window, so the limit is also
// the storage. Past this the control has stopped being a brake anyway: a
// thousand calls an hour is not a session anybody is degrading.
const MaxRate = 1000

// rateRoom answers how many more times this grant may be spent right now,
// and when the next opportunity comes if the answer is none.
//
// limited is false for a grant with no rate at all, which is the common case
// and the one that must stay free: it takes no lock, keeps no timestamps,
// and behaves exactly as it did before this existed.
//
// A window that will not parse means no room and no answer about when. That
// is a hand-edited file, and the fail-closed reading is the only safe one —
// the alternative is that corrupting one string turns a throttled grant into
// an unthrottled one.
// RateRoom is rateRoom for the surfaces that display a grant.
func (g Grant) RateRoom(now time.Time) (room int, next time.Time, limited bool) {
	return g.rateRoom(now)
}

func (g Grant) rateRoom(now time.Time) (room int, next time.Time, limited bool) {
	if g.RateMax == 0 && g.RateWindow == "" {
		return 0, time.Time{}, false
	}
	d, err := time.ParseDuration(g.RateWindow)
	if err != nil || d <= 0 || g.RateMax <= 0 || g.RateMax > MaxRate {
		return 0, time.Time{}, true
	}
	cut := now.Add(-d)
	used, oldest := 0, time.Time{}
	for _, t := range g.Recent {
		if t.After(cut) {
			if used == 0 {
				oldest = t
			}
			used++
		}
	}
	if room = g.RateMax - used; room < 0 {
		room = 0
	}
	if room == 0 && !oldest.IsZero() {
		next = oldest.Add(d)
	}
	return room, next, true
}

// room is how many uses of this grant one call may still take, across both
// budgets, or -1 for "as many as it likes".
//
// A call needs room under every budget the grant carries, so the answer is
// the smaller of them — and a grant carrying neither is not counted at all,
// which is what keeps the unlimited case off the lock.
func (g Grant) room(now time.Time) int {
	left := -1
	if g.MaxUses > 0 {
		if left = g.MaxUses - g.Uses; left < 0 {
			left = 0
		}
	}
	if rr, _, limited := g.rateRoom(now); limited && (left < 0 || rr < left) {
		left = rr
	}
	return left
}

// counted reports whether spending this grant has to be written down, which
// is also whether deciding about it needs the lock.
func (g Grant) counted() bool { return g.MaxUses > 0 || g.RateMax != 0 || g.RateWindow != "" }

// mark records n uses at now, and forgets what has left the window.
//
// The pruning is here rather than on a timer because this is the only code
// with a reason to look, and it is what keeps Recent bounded by the limit
// the operator chose rather than by how long the grant has existed.
func (g *Grant) mark(now time.Time, n int) {
	if _, _, limited := g.rateRoom(now); !limited {
		return
	}
	for i := 0; i < n; i++ {
		g.Recent = append(g.Recent, now.UTC().Truncate(time.Second))
	}
	d, err := time.ParseDuration(g.RateWindow)
	if err != nil || d <= 0 {
		return
	}
	cut := now.Add(-d)
	kept := g.Recent[:0]
	for _, t := range g.Recent {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	g.Recent = kept
	if len(g.Recent) == 0 {
		// nil rather than an empty slice: canonical() is json.Marshal over
		// the parsed grants and `"recent":[]` is not the same bytes as an
		// omitted field, so an empty one left behind would change the seal of
		// a grant nothing had happened to.
		g.Recent = nil
	}
}

// unmark takes back the n most recent timestamps, for a call that failed.
func (g *Grant) unmark(n int) {
	if n >= len(g.Recent) {
		g.Recent = nil
		return
	}
	g.Recent = g.Recent[:len(g.Recent)-n]
}

// Active reports whether the grant still stands at now: its TTL has not
// passed, and — if it names a use limit — it has not been spent.
func (g Grant) Active(now time.Time) bool {
	// MaxTTL is applied here and not only where a grant is issued. Checking it
	// at issue alone means the cap lives in the CLI and the file is trusted to
	// have been written by it — so a grant claiming to expire in 2099 was
	// honoured for seventy years by a rule that reads "a day is already
	// generous". Enforcing it on the way out makes the cap a property of what
	// a grant can *do* rather than of how one is asked for, which is the only
	// version that survives the file being written by something else.
	return now.Before(g.Expires) && now.Before(g.Issued.Add(MaxTTL)) &&
		(g.MaxUses == 0 || g.Uses < g.MaxUses)
}

// Window is the lifetime this grant was issued with, for renew to extend by
// the same amount rather than guess.
//
// TTL when it is recorded; otherwise Expires-Issued, which for a grant that
// has never been renewed is exactly the window it was issued with, and is the
// only answer available for one sealed before TTL existed. Clamped to MaxTTL
// so a hand-edited file cannot turn a renewal into a longer grant than any
// person could have asked for.
func (g Grant) Window() time.Duration {
	if g.TTL != "" {
		if d, err := time.ParseDuration(g.TTL); err == nil && d > 0 {
			return min(d, MaxTTL)
		}
	}
	if d := g.Expires.Sub(g.Issued); d > 0 {
		return min(d, MaxTTL)
	}
	return DefaultTTL
}

// Caller is who is asking and through what.
//
// The four travel together because they are one decision, and because four
// bare strings in a row at a call site is a transposition that compiles: the
// old signature was already `Reserve(c, values, profile, pin, active)`, and
// most of its callers read `Reserve(c, values, "", "", "")`. Swapping the pin
// and the profile there is a security bug no reviewer can see and no type
// checker can catch. Named fields make the same mistake visible.
//
// Every field can only *subtract* authority — see reachable — which is what
// makes it admissible for the MCP server to fill any of them from its own
// session state rather than from the operator's typing.
type Caller struct {
	// Agent is the name `rta mcp serve --as` was launched under, empty for a
	// server launched without one. Compared exactly against Grant.Agent.
	Agent string
	// Profile is the connection this call names, empty for the operator's
	// base configuration. Compared exactly against Grant.Profile.
	Profile string
	// Pin is profile.ConnStamp of the connection this call will actually be
	// filled from, so a grant issued against a different one for the same
	// *name* stops covering it.
	Pin string
	// Active is the environment the operator has switched on, empty when they
	// have not switched. While they are working in one place, a grant naming
	// any other profile does not count.
	Active string
}

// covers reports whether this grant authorizes a call of capID on scope, made
// by this caller.
func (g Grant) covers(capID, scope string, by Caller) bool {
	if g.Target != capID && g.Target != Namespace(capID) {
		return false
	}
	// Exact, in both directions, with no g.Agent == "" escape hatch, for the
	// reason Profile's own check below gives: a grant issued before anybody
	// was named authorizes the unnamed server it was issued to, and does not
	// widen to cover an agent added afterwards.
	if g.Agent != by.Agent {
		return false
	}
	// Exact, in both directions, with no g.Profile == "" escape hatch. A grant
	// for "staging" does not authorize a call naming no profile, and a grant
	// naming no profile does not authorize a call on "staging". See the field
	// comment: this is what makes the arrival of Profile safe for every grant
	// already sealed on disk.
	if g.Profile != by.Profile {
		return false
	}
	// A scoped grant authorizes that record and nothing else — including a
	// call that names no record at all, which is by definition wider.
	if g.Scope == "" || g.Scope == scope {
		return true
	}
	return coversFolder(g.Scope, scope)
}

// coversFolder is the one relaxation of byte-exact scope matching: a scope
// ending in "/" is a folder, and covers the records under it.
//
// **It exists because the granularity had no middle.** A kv store is one
// namespace, so an operator could authorize `kv.get` on one key or on every
// secret they own, and nothing between — which is exactly the pressure that
// makes people type the everything-grant "so it stops failing", the same
// pressure just-in-time consent was written against. Most scope
// dimensions in the catalogue are already slash-separated (kv keys, S3 object
// keys, Vault paths, URLs), so the folder is a boundary the operator can
// already see in a listing.
//
// **The trailing slash is not sugar, it is the security rule.** A bare prefix
// match is the classic boundary bug: a grant for "https://api.example.com"
// would cover "https://api.example.com.evil.com/x", and one for "prod" would
// cover "prod-adjacent". Requiring the separator makes the boundary a real
// one, and leaves a scope without it byte-exact — "prod" still means the
// record named exactly "prod" and nothing else.
//
// **A traversal segment is never covered**, which is the other half and the
// one that is easy to miss. `https://api.example.com/v1/../admin` starts with
// `https://api.example.com/v1/` and a server resolves it to `/admin`, so a
// literal prefix would authorize precisely what the operator scoped away
// from. The same is true of any store that canonicalises a path. A call
// naming such a scope can still be authorized — by an exact grant, where the
// operator has typed that whole strange string themselves and no inference is
// being made on their behalf. What it cannot be is swept in by a folder.
//
// Empty segments are deliberately *not* refused: "https://host/a" splits to
// ["https:", "", "host", "a"], so a blanket rule against them would refuse
// every URL.
// IsFolderScope reports whether a scope names a folder rather than a record.
//
// Exported because the surfaces have to say so: a folder grant and an exact
// grant are different widths, and a row reading "on prod/" looks like one
// record with an odd name.
func IsFolderScope(scope string) bool {
	return strings.HasSuffix(scope, "/") && scope != "/"
}

// MaxAgentName bounds a name the operator invents for themselves. Generous
// for anything readable, and short enough that a row in `grant list` stays a
// row.
const MaxAgentName = 64

// CheckAgent refuses an agent name that could be mistaken for another one.
//
// **The charset is the control, and homoglyphs are the reason.** An agent name
// is compared byte-exactly and displayed to a person, which is the exact
// combination that makes lookalikes dangerous: `claude-desktop` with a
// non-breaking hyphen (U+2011) renders identically to the one with an ASCII
// hyphen in every terminal, so an operator reading `grant list` cannot tell a
// grant for their own agent from a grant for something else. Restricting the
// set to characters that cannot collide removes the whole class rather than
// trying to detect it — and costs nothing, because this is a name the operator
// invents and types twice: once where they wire the client up, once here.
//
// Refused at issue *and* at `rta mcp serve --as`, deliberately the same
// function. A server that accepted a name the grant command refuses could
// never be granted anything, and would say so nowhere.
func CheckAgent(name string) *view.Error {
	if name == "" {
		return nil
	}
	if len(name) > MaxAgentName {
		return view.Errorf("grant.agent.long", "an agent name is at most %d characters", MaxAgentName).
			WithHint("it is a label you choose, not a description")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return view.Errorf("grant.agent.charset",
				"%q is not allowed in an agent name (found %q)", name, string(r)).
				WithHint("letters, digits, - _ and . only — so that two names cannot " +
					"look identical and mean different things")
		}
	}
	return nil
}

// CheckScope refuses a scope that cannot mean what it appears to mean.
//
// A grant is issued once and consulted many times, so a scope that reads like
// a boundary and is not one is worth refusing at the moment somebody types it
// rather than discovering later that it authorized more or less than it
// looked like. "/" alone is refused because a grant over everything is what
// omitting the scope already says, and spelling it as a folder hides that.
func CheckScope(scope string) *view.Error {
	if scope == "/" {
		return view.Errorf("grant.scope.root", "%q would cover every record", scope).
			WithHint("omit the scope entirely to allow the whole target — a grant that " +
				"wide should look wide")
	}
	if !IsFolderScope(scope) {
		return nil
	}
	for seg := range strings.SplitSeq(strings.TrimSuffix(scope, "/"), "/") {
		if seg == "." || seg == ".." {
			return view.Errorf("grant.scope.traversal",
				"%q contains a %q segment, so what it covers depends on who resolves it", scope, seg).
				WithHint("name the folder as it appears in a listing")
		}
	}
	return nil
}

func coversFolder(prefix, scope string) bool {
	if !IsFolderScope(prefix) {
		return false
	}
	if !strings.HasPrefix(scope, prefix) {
		return false
	}
	for seg := range strings.SplitSeq(scope, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Covering returns the first grant in grants that would authorize a call to
// capID on scope, or nil if none does.
//
// It is covers() made visible outside the package, for the one caller that
// legitimately needs to ask the question in the other direction: not "is
// this call allowed" but "after I remove some grants, is this target still
// allowed by what's left". grant.revoke uses it to say so honestly — a row
// naming exactly the target it was asked to revoke can be gone while a
// wider grant still authorizes every call that target would ever make, and
// "No active grant for X" is the wrong thing to print when that is true.
func Covering(grants []Grant, capID, scope string, by Caller) *Grant {
	for i := range grants {
		if grants[i].covers(capID, scope, by) {
			return &grants[i]
		}
	}
	return nil
}

// Namespace is the plugin part of a capability ID: the coarsest thing a grant
// may name.
//
// Delegates to plugin.Namespace rather than deriving it again. Two copies of
// "the part before the first dot" is one too many once internal/profile needs
// the same answer to decide which plugin a profile configures.
func Namespace(capID string) string { return plugin.Namespace(capID) }

// Normalize accepts the forms people type for a target — "kv", "kv.*",
// "kv.get" — and returns the stored one.
func Normalize(target string) string {
	return strings.TrimSuffix(strings.TrimSpace(target), ".*")
}

// Path is where grants are kept.
func Path() string { return filepath.Join(paths.Data(), file) }

// Ceiling is the team's policy in force right now.
//
// **Read on every call rather than cached, and that was measured rather than
// assumed**: the walk costs 7.7µs from a directory six deep, against a Load
// that already reads and HMAC-verifies the grant file on the same path. A
// cache would have bought that back and cost two things worth more — test
// isolation, and the surprise of an operator editing a policy while a running
// server ignores it.
//
// Re-reading is also the better behaviour *because* a ceiling only subtracts:
// a team can tighten one and every running server picks it up on its next
// call, with no restart, and with no way for the change to widen anything.
func Ceiling() (policy.Ceiling, *view.Error) { return policy.Load() }

// CheckCeiling refuses a grant the team's policy does not allow, in words
// that name both the rule and the file.
//
// **A ceiling that applies has to say so out loud.** A silent clamp — issuing
// the 2h grant the operator asked for and quietly storing 15m — teaches them
// to distrust the number they typed, and a grant that vanishes with no
// explanation sends them to debug the agent instead of the policy.
func CheckCeiling(target, scope, profile string) *view.Error {
	c, verr := Ceiling()
	if verr != nil {
		return verr
	}
	why := c.Forbids(target, scope, profile)
	if why == "" {
		return nil
	}
	return view.Errorf("grant.policy.refused", "%s — %s", why, c.Where()).
		WithHint("this is a ceiling, and a ceiling only ever narrows: edit that " +
			"file, or ask whoever shares it")
}

// ClampTTL brings a requested window under the team's ceiling, and reports
// whether it had to. Returning the fact rather than only the value is the
// same rule CheckCeiling states: the caller has a sentence to write.
func ClampTTL(d time.Duration) (time.Duration, bool, string) {
	c, verr := Ceiling()
	if verr != nil || c.MaxTTL <= 0 || d <= c.MaxTTL {
		return d, false, ""
	}
	return c.MaxTTL, true, c.Where()
}

// Suppressed counts the stored grants that would be standing if the team's
// ceiling did not forbid them.
//
// **A ceiling that applies has to say so out loud**, and this is the half
// that is easy to leave out: `grant list` on a machine whose policy has just
// tightened reads "no active grants", which is true of what may happen and
// deeply misleading about what is on disk. An operator reading that goes to
// look for a grant they are sure they issued.
//
// Expired and spent grants are not counted — those are gone on their own
// terms, and reporting them here would make the ceiling look responsible for
// the ordinary passage of time.
func Suppressed() int {
	ceiling, verr := Ceiling()
	if verr != nil || ceiling.Empty() {
		return 0
	}
	all, verr := loadAll()
	if verr != nil {
		return 0
	}
	now := time.Now()
	n := 0
	for _, g := range all {
		if !g.Active(now) {
			continue
		}
		if ceiling.Forbids(g.Target, g.Scope, g.Profile) != "" ||
			(ceiling.MaxTTL > 0 && !now.Before(g.Issued.Add(ceiling.MaxTTL))) {
			n++
		}
	}
	return n
}

// ceilingActive reports whether g may still authorize anything: not
// expired, not fully spent, and not forbidden by ceiling. This is the one
// place that decides it — Load, and Reserve's reachableNow below, both
// call this rather than each keeping their own copy of the rule.
func ceilingActive(g Grant, ceiling policy.Ceiling, now time.Time) bool {
	if !g.Active(now) {
		return false
	}
	if ceiling.Empty() {
		return true
	}
	if ceiling.Forbids(g.Target, g.Scope, g.Profile) != "" {
		return false
	}
	if ceiling.MaxTTL > 0 && !now.Before(g.Issued.Add(ceiling.MaxTTL)) {
		return false
	}
	return true
}

// Load returns the grants that are still active; expired and fully-spent ones
// are dropped on read, so nothing has to sweep them.
func Load() ([]Grant, *view.Error) {
	all, verr := loadAll()
	if verr != nil {
		return nil, verr
	}
	// The team's ceiling is applied here, on the way *out*, for exactly the
	// reason Active() gives for MaxTTL in ceilingActive: checking it only
	// where a grant is issued leaves the cap in the CLI and trusts the file to
	// have been written by it. Applied here it is a property of what a grant
	// can do, which is the version that survives a policy tightening after the
	// grant was issued — and the grant is not deleted, so relaxing the policy
	// brings it back rather than having thrown it away.
	//
	// loadAll deliberately does not do this: the refund path has to find a
	// grant in order to give a use back to it, and a use spent under yesterday's
	// policy must still be refundable under today's. Reserve's locked write
	// path has the same requirement for the same reason — see reachableNow.
	ceiling, verr := Ceiling()
	if verr != nil {
		return nil, verr
	}
	now := time.Now()
	active := make([]Grant, 0, len(all))
	for _, g := range all {
		if ceilingActive(g, ceiling, now) {
			active = append(active, g)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Expires.Before(active[j].Expires) })
	return active, nil
}

// loadAll returns every stored grant, including the ones Load hides.
//
// A grant spent to its last use stops being Active, so Load can no longer see
// it — which is right for every caller that asks "what is allowed" and wrong
// for the one that has to give a use back after a failed call. Refunding
// needs the record Load has already filtered away.
func loadAll() ([]Grant, *view.Error) {
	data, err := atomicfile.ReadCapped(Path(), maxGrantFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, view.Errorf("core.grant.unreadable", "reading %s: %v", Path(), err)
	}
	if legacy(data) {
		// A grant file from before the seal. Every grant in it is dropped and
		// nothing is refused — see seal.go for why that is neither honouring
		// it nor erroring on it.
		return nil, nil
	}
	var doc sealed
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, view.Errorf("core.grant.corrupt", "parsing %s: %v", Path(), err).
			WithHint("delete the file to clear every grant")
	}
	key, verr := sealKey(false)
	if verr != nil {
		return nil, verr
	}
	// Refused loudly rather than treated as no grants. Falling back to empty
	// would be safe for authorization and wrong for the operator: a tampered
	// file would look exactly like "you have not issued any", so the one
	// moment worth noticing would present as the ordinary case.
	canon, err := canonical(doc.Grants)
	if err != nil {
		return nil, view.Errorf("core.grant.corrupt", "re-encoding %s: %v", Path(), err)
	}
	if !seal.Equal(doc.Seal, sealOf(key, canon)) {
		// Nothing is honoured either way; only the sentence differs. A file
		// carrying fields this build never declared fails the seal because
		// canonical() re-encodes what it parsed and drops them — which is what
		// an ordinary downgrade looks like from here, and accusing the
		// operator's own newer rta of forgery while telling them to delete
		// every grant is the wrong reading of it. See unknown().
		if extra := unknown(data); len(extra) > 0 {
			return nil, view.Errorf("core.grant.unknownfields",
				"%s carries grant fields this rta does not know (%s), so its seal cannot be "+
					"checked — it was written by a newer rta, or it has been modified",
				Path(), strings.Join(extra, ", ")).
				WithHint("no grant is honoured either way; upgrade rta to read it, or `rm " +
					Path() + "` to clear every grant and re-issue what you still need")
		}
		return nil, view.Errorf("core.grant.forged",
			"%s does not match its seal — it was written by something other than rta", Path()).
			WithHint("no grant is honoured until this is resolved; `rm " + Path() +
				"` clears every grant, and any that were legitimate can be re-issued")
	}
	// After the seal, so the guard's verdict is about rows the seal already
	// vouched for — the seal keeps the last word on authorship, and a guard
	// statement about bytes the seal disowns would be a statement about
	// nothing. Same all-or-nothing stance, see guardcheck.go.
	if verr := guardChecked(doc.Grants); verr != nil {
		return nil, verr
	}
	return doc.Grants, nil
}

// Save replaces the grant file.
//
// Written atomically (temp file, then rename over the target): the grant lock
// only ever serializes the writers, and a reader — Load, called from Reserve's
// unlocked fast path on every gated MCP call — can still land mid-write
// against a plain os.WriteFile, which truncates before it writes.
// A reader that races a torn file sees valid JSON either way: the old
// complete grants, or the new ones, never a half-written one.
func Save(grants []Grant) *view.Error {
	dir := paths.Data()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return view.Errorf("core.grant.write", "creating %s: %v", dir, err)
	}
	canon, err := canonical(grants)
	if err != nil {
		return view.Errorf("core.grant.write", "encoding grants: %v", err)
	}
	key, verr := sealKey(true)
	if verr != nil {
		return verr
	}
	data, err := json.MarshalIndent(sealed{Seal: sealOf(key, canon), Grants: grants}, "", "  ")
	if err != nil {
		return view.Errorf("core.grant.write", "encoding grants: %v", err)
	}
	// 0600 enforced, not requested: this file is what an agent's authority
	// is read from, so it must not become readable — or writable — because
	// of a permissive umask.
	if err := atomicfile.Write(Path(), data, 0o600); err != nil {
		return view.Errorf("core.grant.write", "writing %s: %v", Path(), err)
	}
	return nil
}

// Issue stores g, replacing any grant it is equivalent to.
//
// write=false previews: the file is still read, and an unreadable one is
// still reported, so a preview cannot promise a grant that would have
// failed.
//
// One grant per target+scope+profile: re-allowing extends the deadline
// rather than stacking two grants whose earlier expiry means nothing.
// Profile is part of the key, and leaving it out would make this
// destructive — `grant allow pg --profile b` would delete the grant for
// profile a while reporting only that b had been allowed, silently
// revoking access nobody asked to revoke. The key has to be exactly what
// covers() distinguishes, or "replace the equivalent grant" replaces one
// that is not equivalent.
//
// Here rather than in builtin/grant because a second caller arrived —
// answering a parked request with --ttl issues exactly the grant the
// operator would have typed — and two implementations of "what counts as
// the same grant" is how the two come to disagree.
func Issue(g Grant, write bool) *view.Error {
	// Refused where somebody is standing and can fix it. Load already stops a
	// forbidden grant authorizing anything, so this is not the enforcement —
	// it is the difference between a grant that never works and never says
	// why, and a refusal naming the rule and the file it came from.
	if verr := CheckCeiling(g.Target, g.Scope, g.Profile); verr != nil {
		return verr
	}
	// Only when something will be written: a preview mints nothing, so it
	// must not demand the passphrase a real issuance would — the dry run is
	// how the TUI and --dry-run describe the grant before anyone commits.
	// Checked *inside* the locked callback rather than out here, so a guard
	// transition cannot interleave: a `guard on` landing between an outside
	// check and the write would persist an unsigned row the next read then
	// refuses as forgery — a false alarm this ordering is cheaper than.
	var guardErr *view.Error
	verr := Mutate(func(stored []Grant) ([]Grant, bool) {
		if write {
			if verr := guardIssuable(g); verr != nil {
				guardErr = verr
				return stored, false
			}
		}
		kept := stored[:0]
		for _, existing := range stored {
			// Agent is part of the key for the reason stated above: it is one
			// of the things covers() distinguishes, so two grants that differ
			// only by who may spend them are two decisions. Leaving it out
			// would make `grant allow kv.get --agent ci` silently revoke the
			// grant the operator's desktop agent was already holding — the
			// exact failure this rule was written after.
			if existing.Target != g.Target || existing.Scope != g.Scope ||
				existing.Profile != g.Profile || existing.Agent != g.Agent {
				kept = append(kept, existing)
			}
		}
		return append(kept, g), write
	})
	if guardErr != nil {
		return guardErr
	}
	return verr
}

// Mutate rewrites the grant file under the lock: it hands f every stored
// grant and saves what f gives back, unless f declines.
//
// It exists because grant.allow and grant.revoke did the same Load-mutate-Save
// round trip with no lock at all, on the file that decides what an AI agent may
// do. A revoke landing inside Reserve's post-lock Load..Save was read, filtered
// and written by the revoker, then written back by Reserve from the snapshot it
// had taken a moment earlier — so `rta grant revoke kv.get` said "revoked 1
// grant(s)" and the grant was in the file again a millisecond later, still
// authorizing calls, still listed by `grant list`. The window is small and
// needs a --max-uses grant to exist at all, which is not a reason to keep it.
// The lock lives here rather than around each caller's round trip so the
// discipline is a property of the package: a capability that edits grants
// tomorrow cannot forget it, because there is no other way to write the file.
//
// f sees loadAll's answer, not Load's. A grant spent to its last use is no
// longer Active, so Load hides it — and a writer that round-trips through Load
// deletes every row it was not shown, merely by saving. That row is exactly the
// one refund reaches for when the guarded call fails, so the use would never
// come back and a one-time grant that revealed nothing would stay spent.
// Deciding over the whole file also means f drops a dead row because it meant
// to, not because of what it happened to be handed.
//
// Returning false stores nothing, which is how --dry-run and "there was nothing
// to revoke" get their answer: what the person is told is decided under the
// same lock as the write it declines, so the message and the file cannot
// disagree.
func Mutate(f func([]Grant) ([]Grant, bool)) *view.Error {
	unlock, verr := acquireLock()
	if verr != nil {
		return verr
	}
	defer unlock()
	stored, verr := loadAll()
	if verr != nil {
		return verr
	}
	next, save := f(stored)
	if !save {
		return nil
	}
	return Save(next)
}

// Required reports whether a capability needs a grant before an agent may
// call it, given the profile the call names.
//
// Destructive is implicit: a capability that permanently removes something is
// exactly what a standing allowlist should not be enough for. Everything else
// opts in, which is how kv.get — a read by the letter of the safety model,
// a leak in practice — ends up here too.
//
// **Naming a profile is itself enough**, and that clause is the whole of the
// profiles feature. plugins/pg declares no NeedsGrant and all six of its
// capabilities are Safety: Read — honestly, since pg.query runs inside a READ
// ONLY transaction — so without it a profile-aware covers() would do nothing
// for pg at all, and "read the database the operator configured" would
// quietly become "read any database the operator has configured".
//
// The alternative was marking pg's capabilities NeedsGrant, which is wrong in
// the other direction: it would gate `rta pg status` against the operator's
// own localhost, where nobody consented to anything because nothing left the
// machine. The requirement belongs to the connection, not to the capability —
// so the zero-config path stays exactly as frictionless as it is today, and
// consent is required at precisely the moment a call reaches somewhere else.
func Required(c plugin.Capability, profile string) bool {
	return profile != "" || c.NeedsGrant || c.Safety == plugin.Destructive
}

// scopes reads the records a call names, from the input the capability
// declared as its scope. A capability with no scope, or a call that names no
// record, yields one empty scope: the call is about the capability itself.
//
// Deduplicated, not just collected: a record named twice in one call (a
// StringSlice-typed scope repeating a value, by mistake or on purpose) used
// to make spend() walk that scope twice in the same call, incrementing
// MaxUses' Uses counter once per occurrence rather than once per record —
// letting a --max-uses 1 grant authorize itself twice within a single call
// that named the same key two ways. Found by review and
// reproduced directly against Reserve.
// Scopes is the records a call names, as a grant would have to name them.
//
// Exported for the consent prompt: the operator is being asked
// about one call, and "which record" is the whole of what distinguishes
// `kv.get db-password` from `kv.get` — the same question a grant answers,
// so it has to be the same answer, from the same code.
func Scopes(c plugin.Capability, values map[string]any) []string { return scopes(c, values) }

func scopes(c plugin.Capability, values map[string]any) []string {
	if c.Scope == "" {
		return []string{""}
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	switch v := values[c.Scope].(type) {
	case string:
		add(v)
	case []string:
		for _, s := range v {
			add(s)
		}
	case []any:
		for _, raw := range v {
			if s, ok := raw.(string); ok {
				add(s)
			}
		}
	case nil:
	default:
		add(numericScope(v))
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// numericScope renders a non-string scope value (an Int-typed Scope field,
// e.g. note.rm's id) the way an operator would type it, not the way Go's
// %v verb does — fmt.Sprint(float64(1000000)) is "1e+06", which a grant
// issued for the operator-typed string "1000000" (rta grant allow note.rm
// 1000000) would never match. An MCP call's JSON number always decodes to
// float64 before it reaches here (internal/mcp/bridge.go calls Reserve on
// the raw decoded values, before plugin.Resolve's numeric coercion), so this
// is the boundary that has to normalise it. A whole-number float is printed
// as a plain integer; anything with a fractional part falls back to %v,
// since no Field.Type this package scopes against is ever a genuine Float.
// Found by review, which demonstrated the mismatch
// directly rather than only asserting it existed.
func numericScope(v any) string {
	if f, ok := v.(float64); ok && f == math.Trunc(f) {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprint(v)
}

// allocate walks the scopes a call names and, for each, greedily picks the
// first grant that covers it and can still afford one more use in this same
// call — a grant already spoken for elsewhere in the call, right up to its
// MaxUses, no longer counts as covering a further scope, so allocation falls
// through to the next grant that does cover it. It returns, per grant index
// touched, how many additional uses this call would spend, and the scopes
// nothing with budget left covers.
//
// checkAgainst and spend used to walk scopes independently — checkAgainst
// asking only "does anything cover this", spend incrementing whatever it
// found with no memory of what earlier scopes in the same call had already
// claimed. A single MaxUses:1 grant with no Scope (or a Scope wide enough to
// cover several records) covered every scope a multi-record call like
// `kv.env key=[a,b,c]` named, so checkAgainst approved the whole call and
// spend then walked the same grant three times in the one Save it made — a
// grant issued to reveal one secret once revealing three, with the budget it
// was capped at blown past in a call that never touched the lock twice.
// Sharing one walk and one tally is what keeps the authorization decision
// and the spend decision looking at the same arithmetic.
func allocate(c plugin.Capability, values map[string]any, grants []Grant, by Caller) (tally map[int]int, missing []string, throttled *Grant) {
	tally = map[int]int{}
	now := time.Now()
	// Whether every scope this call could not get covers *has* a grant that
	// merely ran out of pace, versus at least one scope nothing covers at
	// all. Only the first case is something waiting can fix — see below.
	allThrottled := true
	for _, scope := range scopes(c, values) {
		covered, scopeThrottled := false, false
		for i, g := range grants {
			if !g.covers(c.ID, scope, by) {
				continue
			}
			if room := g.room(now); room >= 0 && tally[i] >= room {
				// This grant's budget is spoken for — by an earlier scope of
				// this same call, or by the window it is inside. Try another,
				// and remember the first one that was merely *out of pace*:
				// a call refused because a rate limit is full is a different
				// answer to the operator than one refused because nobody
				// allowed it, and it is the only one that can say when to
				// come back.
				scopeThrottled = true
				if throttled == nil {
					if _, _, limited := g.rateRoom(now); limited {
						g := g
						throttled = &g
					}
				}
				continue
			}
			if g.counted() {
				tally[i]++
			}
			covered = true
			break
		}
		if !covered {
			missing = append(missing, scope)
			// A scope with no covering grant at all is not something a wait
			// fixes, whatever some OTHER scope in this same call found. One
			// such scope is enough to make "try again later" the wrong
			// answer for the whole refusal — see checkAgainst.
			if !scopeThrottled {
				allThrottled = false
			}
		}
	}
	if len(missing) == 0 || !allThrottled {
		throttled = nil
	}
	return tally, missing, throttled
}

// checkAgainst answers "is this call authorized" against a set of grants
// already in hand, so that the authorization decision can be made under the
// same lock that spends the use.
//
// Every record a call names needs its own cover — `kv env a b c` with a grant
// for `a` is two thirds of a leak, not a partial success.
//
// **Unexported, and it stays that way.** There used to be a Check() wrapping
// this that did its own Load, and it was the package's second gate: it applied
// the pin filter but not the active bound, so the two exported entry points
// answered differently about the same call. Nothing called it — the bridge has
// always called Reserve — but its own doc comment claimed it was "the whole
// enforcement", which is the sentence that would have sent the next caller to
// the weaker of the two. A gate reachable only through the function that
// spends the use cannot drift from it.
func checkAgainst(c plugin.Capability, values map[string]any, grants []Grant, by Caller) *view.Error {
	_, missing, throttled := allocate(c, values, grants, by)
	if len(missing) == 0 {
		return nil
	}
	// A grant that covers this call and is merely out of pace gets its own
	// answer, and the difference matters twice over. To the operator,
	// because "no active grant" sends them to `grant allow` for a grant they
	// already issued. And to the agent, because this is the one refusal that
	// can say *when to come back* — a model told to wait twelve minutes
	// waits, where one told it has no permission retries, and a retry loop
	// against a rate limit is the same flood the consent queue is capped
	// against.
	//
	// It is deliberately not a consent question either: consent asks only on
	// core.grant.required, so an agent cannot spend its way past a budget the
	// operator set by making them answer the same prompt ten more times.
	if throttled != nil {
		return refuseThrottled(c, *throttled)
	}
	// The hint has to name the profile, because a grant that does not name it
	// authorizes nothing: covers() matches the profile exactly, so
	// `rta grant allow pg.status --ttl 15m` issued for a call on "prod"
	// produces a row that looks right in `grant list` and refuses every call it
	// was issued for. A refusal that hands somebody a command which does not
	// fix the problem is worse than one that hands them nothing — they run it,
	// see success, and go looking for the cause somewhere else.
	//
	// The subject is the namespace rather than the capability when a profile is
	// in play: an operator granting access to a connection almost never means
	// "and only the status call".
	return refuseMissing(c, missing, by.Profile, by.Agent)
}

// samePin compares two connection fingerprints.
//
// **An empty pin matches nothing, including another empty pin**, and that
// asymmetry with ordinary string equality is the whole control. Two ways of
// arriving at empty had to be closed, and `==` closed neither:
//
//   - A profiled grant issued before this field existed carries no pin. Left
//     equal to an empty computed stamp it would be honoured, which is exactly
//     the "empty means any" reading Profile's own comment rejects one field up.
//   - ConnStampFor answers empty for a profile that has been deleted, renamed,
//     or stripped of the plugin. A grant naming a connection that no longer
//     exists must authorize nothing rather than everything.
//
// The same load-bearing zero value plugintrust.Set.Trusts uses, for the same
// reason: a caller that could not compute the thing being compared must not
// get "yes" by default.
func samePin(a, b string) bool { return a != "" && a == b }

// reachable drops the grants this call cannot be authorized by, and reports
// each survivor's position in the set it came from.
//
// Two subtractions, and they were two functions until the second one made the
// case for merging them:
//
//   - **active** — the environment the operator has switched on. While they are
//     working in one place, a grant naming any other profile does not count.
//   - **pin** — the connection this call will actually be filled from. A grant
//     issued against a different one does not count, because the name it
//     consented to now resolves somewhere else.
//
// **Both are filters on the grant set, not checks beside it**, and that is the
// whole design. The active bound started as a short-circuit in internal/mcp
// that refused before Reserve, and it was wrong in two ways at once. It
// compared `profileName != active` without excluding the empty profile, so
// switching *anything* on refused every call that named no profile — most of
// the catalogue — and blacked out the whole agent surface with a hint telling
// the operator to issue grants that could not help. And even correct, it
// produced its own refusal, which named every scope the call carried while the
// real check names only the uncovered ones: an agent holding a partial grant
// could tell the two apart and read "the operator is working somewhere else"
// off the difference.
//
// The pin has the same shape and a sharper version of the same leak. A second
// refusal saying "this profile changed since you were granted" separates
// "granted, then edited" from "never granted", disclosing to an agent both that
// the profile exists and that consent was once given for it. Filtering removes
// the second refusal by construction, so the sentence an agent sees is the
// identical one a call with no grant at all gets, out of the same allocate()
// over the same tally.
//
// **It can only subtract**: nothing here adds a grant, widens one, or changes
// which connection a call is filled from. A call naming no profile still
// matches the grants that name none, because covers() already compares the two
// exactly. A grant with a profile and no pin is one issued before the field
// existed, and it is dropped rather than honoured — fail-closed, and it heals
// when the operator re-consents, which is within one TTL because MaxTTL is a
// day.
//
// pin is the stamp of the connection *this call resolves through*, computed by
// the caller from the same config the fill will read. That matters where the
// two can differ: `rta mcp serve` snapshots profiles at startup (so that a
// profile removed from the file stops being reachable at the next start), and
// a pin taken from a fresh read would refuse every call on an environment
// edited since — with "re-issue the grant" as a remedy that could never work,
// because the server would keep computing the older stamp. Computed from what
// the call will use, a mismatch means what it says.
//
// **The positions are the point.** The decision is made over what is left — but
// the *write* goes back to the whole file, and a caller that saved the filtered
// slice would delete every row the filters dropped. That is not hypothetical:
// Reserve did exactly that, so one use-limited call erased the operator's other
// grants, including the stale-pinned row `rta grant list` and `rta doctor`
// exist to show them. The hazard is the one Mutate's own comment names — "a
// writer that round-trips through Load deletes every row it was not shown,
// merely by saving" — reached through two filters instead of one.
//
// Returning positions rather than a filtered copy makes the mistake hard to
// repeat: there is no subset to hand to Save. Merging the two filters into one
// function is the other half of it — the pair used to be callable separately,
// and the one caller that applied only one of them was the package's second,
// weaker gate.
func reachable(grants []Grant, by Caller) (view []Grant, at []int) {
	for i, g := range grants {
		if !callerReachable(g, by) {
			continue
		}
		view = append(view, g)
		at = append(at, i)
	}
	return view, at
}

// callerReachable is reachable's per-grant rule: the profile fence and the
// stale-pin check. Factored out so reachableNow can apply it in the same
// pass as ceilingActive instead of chaining two separately-filtered views —
// see reachableNow for why that chaining is exactly the hazard this
// function's sibling exists to avoid.
func callerReachable(g Grant, by Caller) bool {
	// By the name half: the switch is the whole environment, so an active
	// `staging` keeps a grant naming `staging/analytics` reachable — the
	// instance is inside the place the operator switched on, and dropping it
	// would make activating an environment revoke consent for its own
	// databases.
	if by.Active != "" && g.Profile != "" && config.RefName(g.Profile) != by.Active {
		return false
	}
	if by.Profile != "" && g.Profile == by.Profile && !samePin(g.ProfilePin, by.Pin) {
		return false
	}
	return true
}

// reachableNow is reachable(Load(), by) — but computed in one pass over
// loadAll's complete result, with at indexing straight back into it, rather
// than by calling reachable on Load's already ceiling-and-active-filtered
// slice.
//
// **That chaining was the bug.** Reserve's locked write path used to do
// exactly that — grants, _ := Load(); view, at := reachable(grants, by) —
// which reads as "the write goes back to everything Load returned" and
// sounds like the fix reachable's own doc comment describes for the
// profile/pin filter. It is not: Load already dropped every grant the
// team's ceiling currently forbids before reachable ever saw it, so `at`
// indexed into a slice that was missing those rows from the start, and
// Save(grants) wrote the file back without them — a ceiling-suppressed but
// still-active grant deleted from disk the moment any unrelated
// rate/use-limited grant was spent, silently defeating Load's own
// documented promise that a ceiling "only ever subtracts" and relaxing it
// "brings the grant back rather than having thrown it away".
//
// Composing both filters over all in one pass, the way this function does,
// is what keeps at valid against the slice Reserve actually saves.
func reachableNow(all []Grant, ceiling policy.Ceiling, now time.Time, by Caller) (view []Grant, at []int) {
	for i, g := range all {
		if !ceilingActive(g, ceiling, now) || !callerReachable(g, by) {
			continue
		}
		view = append(view, g)
		at = append(at, i)
	}
	// Same order Load promises everywhere else it is read: soonest-expiring
	// first, so a call two grants could both cover spends the one closer to
	// going to waste rather than whichever happened to load first.
	sort.Sort(byExpiry{view, at})
	return view, at
}

// byExpiry sorts view by expiry while keeping at in step with it — the two
// slices name the same grants, position for position, so a plain
// sort.Slice(view, ...) that moved only view would leave at pointing at the
// wrong rows of the file reachableNow's caller is about to write back to.
type byExpiry struct {
	view []Grant
	at   []int
}

func (b byExpiry) Len() int           { return len(b.view) }
func (b byExpiry) Less(i, j int) bool { return b.view[i].Expires.Before(b.view[j].Expires) }
func (b byExpiry) Swap(i, j int) {
	b.view[i], b.view[j] = b.view[j], b.view[i]
	b.at[i], b.at[j] = b.at[j], b.at[i]
}

// identity names a grant across a reload.
//
// The fields runAllow dedupes on, plus the moment of consent — which together
// are what makes two rows the same decision rather than two decisions that
// happen to look alike. Needed because a refund runs after the grant file has
// been written and re-read, so an index means nothing by then, and matching by
// "the first row that covers this" is what let a refund give back a use it
// never spent.
type identity struct {
	target, scope, profile, pin, agent string
	issued                             time.Time
}

func (g Grant) identity() identity {
	return identity{g.Target, g.Scope, g.Profile, g.ProfilePin, g.Agent, g.Issued}
}

// spentUse records that this call took n uses from one specific grant, so the
// refund can give back exactly that and nothing else.
type spentUse struct {
	who identity
	n   int
}

// Stale reports whether this grant names a connection that no longer matches
// the one it was issued against.
//
// For the surfaces where a *person* is looking — `rta grant list`, `rta
// doctor` — which is where the remedy belongs, because the remedy names the
// profile and the agent-facing refusal deliberately does not. Computed by
// asking the same filter the gate asks, so a row cannot be marked stale by one
// rule and refused by another.
func (g Grant) Stale(pin string) bool {
	return g.Profile != "" && !samePin(g.ProfilePin, pin)
}

// refuseMissing is the sentence a call gets when nothing authorizes it.
func refuseMissing(c plugin.Capability, missing []string, profile, agent string) *view.Error {
	if len(missing) == 0 {
		missing = []string{""}
	}
	// The hint has to name the profile, because a grant that does not name it
	// authorizes nothing: covers() matches the profile exactly, so
	// `rta grant allow pg.status --ttl 15m` issued for a call on "prod"
	// produces a row that looks right in `grant list` and refuses every call it
	// was issued for. A refusal that hands somebody a command which does not
	// fix the problem is worse than one that hands them nothing — they run it,
	// see success, and go looking for the cause somewhere else.
	//
	// The subject is the namespace rather than the capability when a profile is
	// in play: an operator granting access to a connection almost never means
	// "and only the status call".
	// Quoted only when it has to be: kv places no restriction on a key's
	// characters, so a scope like "db password" built into this hint by
	// plain concatenation produces a command that is not the one command it
	// looks like — a shell splits it into an extra argument. Quoting only
	// the scopes that need it keeps the common case (a bare word) reading
	// exactly as it always has.
	scope := shellQuoteIfNeeded(missing[0])
	what := strings.TrimSpace(c.ID + " " + scope)
	if profile != "" {
		what = strings.TrimSpace(Namespace(c.ID)+" "+scope) + " --profile " + profile
	}
	// And the agent, for the same reason as the profile: covers() matches
	// it exactly, so on a server started `--as claude` the command without
	// `--agent claude` issues a row that authorizes nothing.
	if agent != "" {
		what += " --agent " + shellQuoteIfNeeded(agent)
	}
	return view.Errorf("core.grant.required", "no active grant for %s", describe(c.ID, missing)).
		WithHint("a person has to allow this first: rta grant allow " + what + " --ttl 15m")
}

// shellQuoteIfNeeded wraps s in POSIX single quotes when it contains
// anything a shell would treat as a word boundary or a metacharacter, so a
// hint built by string concatenation stays the one copy-pasteable command it
// claims to be. Left bare when every character is already shell-safe, which
// covers every scope this codebase's own tooling ever generates — this only
// matters for a scope a person or a plugin typed by hand.
func shellQuoteIfNeeded(s string) string {
	if s == "" {
		return s
	}
	safe := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./:@%", r):
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	// The POSIX way to embed a literal single quote inside a single-quoted
	// string: close the quote, emit an escaped quote, reopen it.
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// refuseThrottled is the answer for a call a grant covers and a budget will
// not let through yet.
//
// It names the pace rather than the grant's identity: an agent that has been
// using this grant already knows it exists, and what it does not know — and
// what turns a retry loop into a wait — is how long to leave it. The code is
// its own, so nothing downstream mistakes a full budget for a missing grant:
// `rta doctor` reads it, and consent deliberately does not ask about it.
func refuseThrottled(c plugin.Capability, g Grant) *view.Error {
	_, next, _ := g.rateRoom(time.Now())
	e := view.Errorf("core.grant.rate",
		"the grant for %s allows %d %s per %s and that is spent",
		g.Target, g.RateMax, plural(g.RateMax, "call", "calls"), g.RateWindow)
	if next.IsZero() {
		// A window that would not parse: the grant cannot say when, and
		// guessing would be worse than admitting it.
		return e.WithHint("the operator can re-issue it with `rta grant allow " + g.Target + "`")
	}
	wait := time.Until(next).Truncate(time.Second)
	if wait < time.Second {
		wait = time.Second
	}
	return e.WithHint(fmt.Sprintf("try again in %s — this is a pace the operator set, not a missing permission", wait))
}

// plural is one word or two, for the sentences above.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// describe names what was refused the way the person issuing the grant will
// have to type it.
func describe(capID string, scopes []string) string {
	if len(scopes) == 1 && scopes[0] == "" {
		return capID
	}
	named := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s == "" {
			named = append(named, capID)
			continue
		}
		named = append(named, capID+" "+s)
	}
	return strings.Join(named, ", ")
}

// Reserve authorizes a call and spends its use in one atomic step, returning
// a release to call if the call then fails.
//
// **This is the gate.** Not one of two — the only exported way to ask whether
// a call is authorized, and the only thing that spends a use. It has to be one
// step. The sequence it replaces was check -> Run -> consume, with the lock
// held only by the consume: two concurrent tool calls both read Uses=0 against
// MaxUses=1, both cleared the check, and both ran. The go-sdk dispatches every
// tools/call in its own goroutine, so an agent pipelining two requests is the
// normal case rather than an exotic one — and the outcome was that a grant
// documented as "read this value exactly once" delivered the secret twice,
// then recorded a single use, leaving no trace in `grant list` that it had
// happened.
//
// Spending before the call and refunding on failure keeps the property the
// old ordering was protecting — a transient failure must not burn a one-time
// grant that delivered nothing — while closing the window, because the
// decision and the spend now happen under the same lock.
//
// Grants with no use limit (MaxUses == 0, everything issued before the field
// existed, and the overwhelming common case) never take the lock: there is
// nothing to spend, and the unlocked checkAgainst is a correct and complete
// answer for them.
//
// active is the environment the operator currently has switched on, or "", and
// pin is the connection this call resolves through. Both only ever subtract —
// see reachable().
func Reserve(c plugin.Capability, values map[string]any, by Caller) (release func(), verr *view.Error) {
	if !Required(c, by.Profile) {
		return func() {}, nil
	}
	grants, verr := Load()
	if verr != nil {
		return nil, verr
	}
	view, _ := reachable(grants, by)
	if !anyLimited(view) {
		// Checked against this same snapshot — checkAgainst, not Check, which
		// would Load again. A second, independent read here reopened exactly
		// the window this function exists to close: a MaxUses grant created
		// in the gap between the two reads would be invisible to the
		// snapshot that decided nothing needed spending, yet visible (and
		// authorizing) to a fresh reload, so the call would run on a grant
		// that never recorded the use — "read this once" delivering the
		// secret for free. One read, reused for both the spend decision and
		// the authorization decision, makes that impossible: whatever this
		// call is authorized against is exactly what it already knows has
		// nothing to spend.
		return func() {}, checkAgainst(c, values, view, by)
	}

	unlock, verr := acquireLock()
	if verr != nil {
		return nil, verr
	}
	defer unlock()

	// Re-read under the lock: the unlocked Load above is only a fast path for
	// deciding whether a lock is needed at all. loadAll here, not Load — the
	// write below goes back to everything the file holds, and reachableNow is
	// what keeps at indexing correctly into that full slice rather than into
	// a copy Load has already dropped rows from. See reachableNow's doc
	// comment for the incident that made this the rule.
	all, verr := loadAll()
	if verr != nil {
		return nil, verr
	}
	ceiling, verr := Ceiling()
	if verr != nil {
		return nil, verr
	}
	view, at := reachableNow(all, ceiling, time.Now(), by)
	if verr := checkAgainst(c, values, view, by); verr != nil {
		return nil, verr
	}
	// The tally is over the view; the write is over everything loadAll
	// returned. Saving the view instead — or a view whose positions were
	// computed against anything less than the full file — is how one call
	// came to erase the operator's other grants; see reachableNow.
	tally, missing, _ := allocate(c, values, view, by)
	if len(missing) > 0 || len(tally) == 0 {
		// checkAgainst just approved every scope, so missing is unreachable
		// here; a scope that could not be covered must not silently spend the
		// ones that could.
		return func() {}, nil
	}
	now := time.Now()
	spent := make([]spentUse, 0, len(tally))
	for i, n := range tally {
		all[at[i]].Uses += n
		all[at[i]].mark(now, n)
		spent = append(spent, spentUse{who: all[at[i]].identity(), n: n})
	}
	if verr := Save(all); verr != nil {
		return nil, verr
	}
	return func() { _ = refund(spent) }, nil
}

// refund gives back the uses a call spent, for a call that then failed.
//
// **It gives back what was taken, from the grants it was taken from.** The
// first version recomputed: it walked the call's scopes and, for each, gave a
// use back to the first grant that covered it, restarting the search every
// time. Where one call had spent uses on two different grants — an ordinary
// multi-record call against a wide grant and a narrow one — that walked into
// the same grant twice, giving back a use the call never took there and
// leaving the narrow grant paid for a call that failed. The operator's budget
// stayed the same size and moved: a use they had scoped to one record became a
// use on any record.
//
// Recomputing was wrong for a second reason, too. The state it recomputes
// against is the state *after* the spend, and other calls may have run in
// between — so "the first covering grant with a use to give" is a question
// about now, and the only correct question is what this call took.
func refund(spent []spentUse) *view.Error {
	if len(spent) == 0 {
		return nil
	}
	unlock, verr := acquireLock()
	if verr != nil {
		return verr
	}
	defer unlock()
	// loadAll, not Load: spending the last use makes a grant inactive, so the
	// record that needs the refund is exactly the one Load hides.
	grants, verr := loadAll()
	if verr != nil {
		return verr
	}
	changed := false
	for _, s := range spent {
		for i := range grants {
			if grants[i].identity() != s.who {
				continue
			}
			// Never below zero: a concurrent revoke-and-reissue could put a
			// fresh row here, and a refund must not mint uses.
			if give := min(s.n, grants[i].Uses); give > 0 {
				grants[i].Uses -= give
				// And the pace with it. A call that failed did not spend the
				// operator's minute any more than it spent their use, and
				// leaving the timestamps behind would make a flaky capability
				// look like a busy agent.
				grants[i].unmark(give)
				changed = true
			}
			break
		}
	}
	if !changed {
		return nil
	}
	// Prune on the way out, the same rule Load applies on the way in, so a
	// refund does not resurrect anything that expired while the call ran.
	now := time.Now()
	keep := make([]Grant, 0, len(grants))
	for _, g := range grants {
		if g.Active(now) {
			keep = append(keep, g)
		}
	}
	return Save(keep)
}

func anyLimited(grants []Grant) bool {
	for _, g := range grants {
		if g.counted() {
			return true
		}
	}
	return false
}

const (
	lockFile = "grants.json.lock"
	// lockStale reclaims a lock left behind by a process that crashed while
	// holding it, rather than waiting on it forever.
	lockStale   = 5 * time.Second
	lockRetry   = 10 * time.Millisecond
	lockTimeout = 2 * time.Second
)

// acquireLock serializes read-modify-write access to the grant file across
// processes and goroutines: two MCP tool calls spending the same one-time
// grant at once — plausible under `rta mcp serve --http`, or two `rta mcp
// serve` processes sharing one data directory — must not both see it
// unspent and both succeed. A plain Load-then-Save round trip has no such
// guarantee. Every writer takes it: the belief that a person issuing or
// revoking a grant at a terminal is serialized by there being one person
// typing one command at a time is true of the other people and false of the
// MCP server, which is spending uses in another process the whole time — that
// assumption is what let grant.revoke's unlocked round trip lose a revocation
// to a concurrent Reserve. Writes go through Mutate, Reserve or refund, and
// all three hold this.
//
// The lock is a sentinel file, not flock(2): creating a name that cannot
// already exist behaves identically on every platform rta ships for (Linux,
// macOS, Windows), where POSIX file locking does not.
//
// **The lock is held by identity, not by name.** Every operation on the
// sentinel used to be by path — release removed whatever was there, and a
// waiter that judged the lock stale removed whatever was there — and a name
// is not the file you looked at. Two waiters both finding a crashed holder's
// lock both removed it and both created their own, so both held it; a holder
// whose lock had been broken as stale removed its successor's on the way out.
// Either way two processes are inside a read-modify-write the lock exists to
// serialize, which puts back exactly the lost revocation described above. So
// the sentinel now carries a token, acquiring it is a Publish that reports
// whose token won, releasing it is a no-op unless the token is still ours,
// and breaking a stale one moves the file first and confirms by identity that
// it moved the one it judged.
func acquireLock() (release func(), verr *view.Error) {
	path := filepath.Join(paths.Data(), lockFile)
	release, err := filelock.Acquire(path, lockStale, lockRetry, lockTimeout)
	if err != nil {
		return nil, view.Errorf("core.grant.lock", "acquiring the grant file lock: %v", err)
	}
	return release, nil
}

// RevokeProfile drops every grant naming an environment, and reports how many
// of them were still standing.
//
// Called wherever a profile stops existing. A grant for a name nothing can
// look up authorizes nothing — internal/profile.Lookup refuses it — so leaving
// it behind is a row in `rta grant list` that reads like access and is not,
// which is the one thing a record of consent must never contain.
//
// Here rather than in the surface that deletes, because there are now two of
// them: the TUI's delete action and `rta profile rm`. A rule about what
// happens to a grant belongs with the grants.
func RevokeProfile(name string, now time.Time) int {
	revoked := 0
	_ = Mutate(func(stored []Grant) ([]Grant, bool) {
		revoked = 0
		kept := make([]Grant, 0, len(stored))
		for _, g := range stored {
			// By the name half: deleting an environment deletes its
			// instances, so a grant naming `staging/analytics` must not
			// outlive `staging` as a row that reads like access.
			if config.RefName(g.Profile) == name {
				if g.Active(now) {
					revoked++
				}
				continue
			}
			kept = append(kept, g)
		}
		return kept, revoked > 0 || len(kept) != len(stored)
	})
	return revoked
}

// Where a grant can come from. Three values and no more: the question a
// reader has is "was somebody there", and finer provenance would be a claim
// about identity that nothing here can back.
const (
	// FromForm is a TUI form — a person, unambiguously.
	FromForm = "form"
	// FromTerminal is the CLI with a terminal on the other end.
	FromTerminal = "terminal"
	// FromOperatorPrefix marks a grant issued over the remote operator
	// channel; the rest of the value is the enrolled roster label whose key
	// signed it. A prefix rather than a bare word because the label is the
	// attribution — on a multi-operator server, "operator" alone would name
	// a role, and the roster promised a person.
	FromOperatorPrefix = "operator:"
	// FromCommand is the CLI with nobody there: a provisioning script, a CI
	// job, or an agent's shell tool. All three are legitimate and only one of
	// them is a surprise, which is why this is reported and never refused.
	FromCommand = "command"
)

// Origin names where a request to issue a grant came from.
//
// A TUI request is a form. Everything else is the CLI, and the question that
// remains is whether a person is on the other end of it — the same test
// builtin/kv uses before it decides whether it may ask for a passphrase, and
// for a related reason: both are asking "is anybody there".
func Origin(surface plugin.Surface, interactive bool) string {
	switch {
	case surface == plugin.SurfaceTUI:
		return FromForm
	case interactive:
		return FromTerminal
	default:
		return FromCommand
	}
}

// Watched reports whether a person was present when this grant was issued.
// An old grant with no origin recorded answers false, and callers say
// "unknown" rather than "nobody" — see From.
func (g Grant) Watched() bool { return g.From == FromForm || g.From == FromTerminal }
