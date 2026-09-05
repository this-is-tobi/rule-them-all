// Package mcp bridges the capability registry to a Model Context Protocol
// server. Every capability becomes an MCP tool generated from the same
// declared inputs the CLI uses — zero per-capability work.
//
// Safety gate: only read capabilities are exposed by default. Write requires
// an explicit opt-in; destructive requires a per-capability allowlist. The
// gate is enforced host-side — annotations are advisory for clients, never
// our enforcement mechanism.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/this-is-tobi/rta/internal/agentlog"
	"github.com/this-is-tobi/rta/internal/config"
	"github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/guard"
	"github.com/this-is-tobi/rta/internal/lockdown"
	"github.com/this-is-tobi/rta/internal/pathguard"
	"github.com/this-is-tobi/rta/internal/profile"
	"github.com/this-is-tobi/rta/internal/registry"
	"github.com/this-is-tobi/rta/internal/textclean"
	"github.com/this-is-tobi/rta/internal/toolcall"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// NewServer builds an MCP server exposing the registry's capabilities.
func NewServer(reg *registry.Registry, version string, opts Options) *sdk.Server {
	// The gate reads provenance from the catalogue it is gating, and this is
	// the line that makes forgetting impossible: a caller who does not set
	// Origin gets the registry they already handed over, not a lookup that
	// answers "unknown" for everything.
	//
	// The earlier shape of this fix was a BuiltIn set the caller had to
	// populate, and it was wrong for exactly the reason this line exists — a
	// security control whose zero value silently removes functionality
	// teaches people to fill in a field rather than to be right. Defaulting
	// it here means the only way to get an unwired gate is to pass a lookup
	// on purpose.
	if opts.Origin == nil {
		opts.Origin = reg.Origin
	}
	// Snapshot the guard before serving anything — see the check beside
	// grant.Reserve for what this closes. Taken here so every handler shares
	// one observation: a server that read the state fresh per call would
	// believe the rollback the pin exists to catch.
	opts.guardPin = guard.TakePin()
	// The lock pin is the opposite temperament for the opposite reason: it
	// re-reads per call, because a lock placed mid-incident must land on the
	// next request — while remembering the last verified set, so deleting
	// the file is not an unlock for the process an attacker is talking
	// through. One pin per server, shared by every handler.
	opts.locks = lockdown.NewPin()
	server := sdk.NewServer(&sdk.Implementation{
		Name:    "rta",
		Title:   "Rule Them All",
		Version: version,
	}, &sdk.ServerOptions{
		// The handshake is the moment a client exists: before it there is
		// a process nobody has spoken to, after it an agent that may call.
		InitializedHandler: func(_ context.Context, req *sdk.InitializedRequest) {
			if opts.Connected == nil {
				return
			}
			var info *sdk.Implementation
			if req != nil && req.Session != nil {
				if p := req.Session.InitializeParams(); p != nil {
					info = p.ClientInfo
				}
			}
			opts.Connected(implementationName(info))
		},
	})

	known := map[string]bool{}
	for _, c := range reg.Capabilities() {
		if !opts.exposed(c) || !opts.remoteExposed(c) {
			continue
		}
		server.AddTool(toolDef(c, opts), handler(c, opts, reg))
		known[toolcall.Name(c.ID)] = true
	}
	server.AddReceivingMiddleware(recordUnknownTools(known, opts))
	return server
}

// recordUnknownTools writes a row for a tools/call naming a tool the
// catalogue does not have. The SDK answers those itself, before any handler
// runs, and so before the record was written: an agent reaching for
// grant_allow or kv_rm on a server that did not expose them left no trace,
// and those are exactly the calls an operator grepping outcome=refused is
// looking for. The name is bounded and cleaned like a client's own name,
// because it is the caller's to choose.
func recordUnknownTools(known map[string]bool, opts Options) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "tools/call" {
				if r, ok := req.(*sdk.CallToolRequest); ok && r.Params != nil && !known[r.Params.Name] {
					name := cut(textclean.Terminal(r.Params.Name), maxClientName)
					rec := agentlog.Entry{
						Tool: name, Outcome: agentlog.Refused, Auth: agentlog.Blocked,
						Agent: opts.Agent, Client: clientName(r), Credential: credentialName(ctx),
						Session: opts.Session, Code: "core.mcp.unknown", Reason: "no such tool on this server",
					}
					record(rec)
				}
			}
			return next(ctx, method, req)
		}
	}
}

// reg is passed rather than read off Options because it is what the gate needs
// and forgetting it must not be possible: NewServer already holds the registry
// this catalogue came from, so wiring it here means there is no field a caller
// can leave nil and lose a check with.
func handler(c plugin.Capability, opts Options, reg *registry.Registry) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (res *sdk.CallToolResult, err error) {
		// Every call is recorded, whatever becomes of it: the
		// refusals are the half an operator most wants back. The zero
		// values say "refused before anything could authorize it", which
		// is what an exit before the gate actually was.
		rec := agentlog.Entry{
			Cap: c.ID, Tool: toolcall.Name(c.ID),
			Outcome: agentlog.Refused, Auth: agentlog.Blocked,
			Agent: opts.Agent, Client: clientName(req), Credential: credentialName(ctx),
			Session: opts.Session,
		}
		// A panic anywhere in call() — in a capability's own Run, or in this
		// package — must cost this one call, not every other agent and tool
		// attached to the same `mcp serve` process. go-sdk runs each
		// tools/call in its own unrecovered goroutine, so nothing upstream of
		// this catches it: an unrecovered panic here takes the whole server
		// down mid-flight for everyone, from the least-privileged caller the
		// surface has. Recovered rather than left to crash, the same
		// direction refusedBy already treats every other failure: the record
		// still gets written, and the caller gets a refusal instead of a
		// hang-up.
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "rta: %s panicked, recovered: %v\n%s\n", c.ID, r, debug.Stack())
				verr := view.Errorf("core.mcp.panic", "%s failed unexpectedly", c.ID)
				refusedBy(&rec, verr)
				res, err = errResult(verr), nil
			}
			record(rec)
		}()
		res, err = call(ctx, c, opts, reg, req, &rec)
		return res, err
	}
}

// call is the handler's body, with rec filled in as it goes so that the one
// place that writes the ledger sees what happened on every path.
func call(ctx context.Context, c plugin.Capability, opts Options, reg *registry.Registry,
	req *sdk.CallToolRequest, rec *agentlog.Entry) (*sdk.CallToolResult, error) {
	// The frozen check comes before every other gate — validation, paths,
	// grants, consent — because it answers a different question: not "may
	// this call proceed" but "is this caller allowed to ask". A locked
	// principal is refused outright and never parked as a consent question:
	// a lock is the "stop asking me" control for an incident in progress,
	// and it covers the read tier the grant gate never touches — which is
	// exactly the surface a misbehaving agent's bearer token still opened
	// after every grant was revoked.
	if l, alarm := opts.locks.Check(opts.Agent, credentialName(ctx)); l != nil || alarm != "" {
		if alarm != "" {
			fmt.Fprintf(os.Stderr, "rta: %s\n", alarm)
		}
		if l != nil {
			verr := lockdown.Refusal(l)
			refusedBy(rec, verr)
			return errResult(verr), nil
		}
	}
	{
		values := map[string]any{}
		if raw := req.Params.Arguments; len(raw) > 0 {
			if err := json.Unmarshal(raw, &values); err != nil {
				verr := view.Errorf("core.mcp.badargs", "arguments must be a JSON object").
					WithHint(err.Error())
				refusedBy(rec, verr)
				return errResult(verr), nil
			}
			// `"arguments": null` is legal JSON and legal MCP — the field is
			// optional and clients do send it explicitly — and unmarshalling
			// null into a map sets the map to nil rather than leaving the
			// empty one alone. Every write below then panics, which on this
			// surface means one schema-valid call from an unprivileged agent
			// killing `rta mcp serve` for every tool attached to it. Found by
			// a test that passed nil arguments to a capability that declares
			// a default; the panic needs both, which is why four hundred
			// tests missed it.
			if values == nil {
				values = map[string]any{}
			}
		}
		// The published schema says integer, enum, array-of-string — and
		// nothing between here and the handler enforces any of that. The SDK
		// says so itself: unmarshalling and validating against the schema are
		// the caller's responsibility (go-sdk's Server.AddTool doc comment).
		// Without this, a wrong-typed argument was indistinguishable from an
		// omitted one — Request.Int and Request.String both return the zero
		// value on a type mismatch rather than reporting one — so
		// sys_ps {"limit": "3"} (schema: integer) silently returned every
		// process at the default limit instead of three, no error, no
		// warning. Checked against what the caller actually sent, before
		// defaults or Local-stripping touch the map: a default is our own
		// value and always well-typed, so only what arrived over the wire
		// needs the scrutiny.
		if verr := toolcall.Validate(c, values); verr != nil {
			refusedBy(rec, verr)
			return errResult(verr), nil
		}
		// The profile comes out of the arguments here — before defaults, before
		// Local-stripping, and above all before the gate — because it is the
		// host's, not the capability's. "profile" is a reserved input name, so
		// no plugin can declare one and no handler will ever see it in its
		// Request.
		//
		// **The decoded argument is the only source.** Not config, not a
		// session file, not an environment variable: the string the gate checks
		// and the string the call is filled from have to be the same string by
		// construction, or a person's consent and the connection that was
		// actually touched can disagree. `rta use` deliberately does not reach
		// this surface for exactly that reason.
		profileName, verr := takeProfile(c, values, opts)
		if verr != nil {
			refusedBy(rec, verr)
			return errResult(verr), nil
		}
		rec.Profile = profileName
		// Declared defaults apply to omitted arguments, exactly like the CLI.
		// Local fields are dropped whatever the caller sent: they are absent
		// from the schema, so anything arriving under that name was guessed,
		// and a guessed credential is the one case worth discarding rather
		// than acting on. Dropped, not refused the way an undeclared name is:
		// an error naming the field would confirm to the model that the
		// credential input exists, which is the disclosure Local is for.
		for _, f := range c.Inputs {
			if f.Local {
				delete(values, f.Name)
				continue
			}
			if _, given := values[f.Name]; !given && f.Default != nil {
				values[f.Name] = f.Default
			}
		}
		if verr := toolcall.Require(c, values); verr != nil {
			refusedBy(rec, verr)
			return errResult(verr), nil
		}
		// Recorded here: after Local fields are gone and defaults are in,
		// so the ledger shows the call as it would actually run — and
		// before the gate, so a refusal records what was asked for.
		rec.Args = auditArgs(c, values)
		// After defaults, deliberately, and this used to be before them.
		//
		// The old ordering exempted declared defaults from the root check, on
		// the grounds that a default is the plugin's own choice rather than
		// the caller's, and cited `net.hosts.list` defaulting to /etc/hosts.
		// **That capability declares no default** — /etc/hosts is a handler
		// constant (builtin/net/net.go's hostsFile), so the exemption's one
		// stated beneficiary never used it. Its only real users were three
		// inputs declaring `Default: "."` — audit.deps, fs.tree, fs.usage —
		// where "." is not a considered choice of a system file but "wherever
		// this server happened to be launched", which is the exact thing
		// --root exists to overrule.
		//
		// Reproduced: with --root elsewhere, `fs_tree {"path": "<cwd>"}` was
		// refused with core.mcp.path.outside while `fs_tree {}` read that same
		// directory and returned its contents. The guard must see the values
		// that will actually be used, not the subset the caller happened to
		// type. A default outside the root is now refused like anything else;
		// where root and cwd are the same — every run without --root — nothing
		// changes.
		//
		// The type check above stays before defaults, because its reason does
		// survive: a default is rta's own value and is always well-typed, so
		// only what arrived over the wire needs that scrutiny.
		if verr := checkPaths(c, values, opts.Paths); verr != nil {
			refusedBy(rec, verr)
			return errResult(verr), nil
		}
		// The exposure gate said this agent may in principle make this kind of
		// call. A grant says a person allowed this one, on this record, now —
		// the second half of the MCP equivalent of a confirmation. Enforcing
		// it here rather than in each handler is what makes it a property of
		// the surface instead of something a plugin can forget.
		// Authorize and spend in one step. Checking first and spending after
		// the call left a window every concurrent caller fitted through: the
		// go-sdk dispatches each tools/call in its own goroutine, so two
		// pipelined requests both cleared an unlocked check against a
		// MaxUses:1 grant and both received the secret. Reserve decides and
		// increments under the same lock, and hands back a refund for the
		// case the old ordering existed to protect — a call that fails must
		// not burn a one-time grant that delivered nothing.
		// The operator's switch goes *into* the gate rather than beside it.
		//
		// While they are working in one environment, agents are in that
		// environment and nowhere else: grant.bounded drops every grant naming
		// another profile, so a grant for somewhere else stays issued and stays
		// unusable until they switch back. It is the fastest way to take reach
		// away from an agent without revoking anything.
		//
		// Passed in rather than checked here, and that is the whole lesson of
		// the first attempt: a separate check produced its own refusal, which an
		// agent holding a partial grant could tell apart from the real one — and
		// got the empty-profile case wrong, refusing every call that named no
		// profile at all. One decision, one sentence, one place.
		//
		// It can only subtract: it never supplies a profile to a call that named
		// none, never satisfies R5, and never turns a refusal into an approval.
		// That direction is the whole reason session state is admissible on this
		// surface — an expanding session input would let a person's consent and
		// the connection actually touched disagree.
		//
		// The pin goes in the same way and for the same reasons: it is the
		// fingerprint of the connection this call would be filled from, so a
		// grant issued against a different one for the same *name* stops
		// covering it. Computed from the same read profile.Lookup uses below,
		// so a mismatch means "you consented to a different connection" and
		// never "this process has not noticed your edit".
		//
		// The agent name goes in the same way and subtracts in the same
		// direction: it is the operator's own word for the client at the far
		// end of this pipe, so a grant issued while talking to one agent no
		// longer authorizes every other one on the machine.
		//
		// Before any grant is honoured: the guard this server started under
		// must still stand. The pin lives in this process's memory, which is
		// the one place a same-uid `rm guard.json grants.json` cannot reach —
		// on disk that rollback looks exactly like a machine where the guard
		// was never enabled, but the attacker performing it is talking
		// *through* this process, and this process remembers. Checked here
		// rather than at the top of call() because it guards grant-minted
		// authority specifically: a weakened guard says nothing about the
		// read-tier surface that never needed a grant. Never parked as a
		// consent question either — a tampered state is an alarm for the
		// operator, not a request from the agent.
		if verr := opts.guardPin.Check(); verr != nil {
			// Through the same refusal path every gate uses, not a protocol
			// error: the ledger entry is half the point — the alarm belongs
			// in `rta agent log`, timestamped beside whatever the caller was
			// doing when the guard vanished.
			refusedBy(rec, verr)
			return errResult(verr), nil
		}
		release, verr := grant.Reserve(c, values, grant.Caller{
			Agent:   opts.Agent,
			Profile: profileName,
			Pin:     opts.connStamp(profileName, grant.Namespace(c.ID)),
			Active:  opts.active(),
		})
		if verr != nil {
			// Nobody pre-authorized it. With consent enabled, that is a
			// question rather than an answer: park the call, ask the
			// person, and proceed on their word.
			// Everything about the refusal is preserved for the case where
			// the answer never comes.
			allowed, decided := askConsent(ctx, c, opts, values, profileName, verr, rec)
			if !allowed {
				if decided == nil {
					// Never asked: the refusal is the gate's own.
					refusedBy(rec, verr)
					return errResult(verr), nil
				}
				return errResult(decided), nil
			}
			// The lock check at the top ran before this call parked, and a
			// call can wait in the queue for minutes — long enough for the
			// operator to lock the very principal that asked. During an
			// incident, "lock add" must poison what is already parked, not
			// only what asks next, so the pin is consulted again on the way
			// out of consent: an approval races a lock, the lock wins.
			if l, _ := opts.locks.Check(opts.Agent, credentialName(ctx)); l != nil {
				verr := lockdown.Refusal(l)
				refusedBy(rec, verr)
				return errResult(verr), nil
			}
			// Approved live: there is no grant, so there is no use to
			// refund either.
			release = func() {}
		} else if grant.Required(c, profileName) {
			rec.Auth = agentlog.Standing
		} else {
			rec.Auth = agentlog.Open
		}
		// Only now, with consent in hand, is the profile resolved. The order
		// matters and is asserted: an unknown profile and an ungranted one must
		// produce the same refusal, so a caller cannot use the difference to
		// enumerate the operator's connections. Looking up first would answer
		// "no such profile" for a name that does not exist and "needs a grant"
		// for one that does, which is the whole inventory one call at a time.
		var filled map[string]any
		if profileName != "" {
			conn, verr := profile.Lookup(opts.profiles(), c, profileName, reg)
			if verr != nil {
				release()
				rec.Outcome, rec.Code = agentlog.Refused, "core.profile.unusable"
				// The reason is deliberately discarded on this surface. A person
				// at a terminal gets profile.Lookup's real message and its list
				// of what would have worked; an agent gets one sentence for
				// every way a profile can be unusable, so the refusal cannot be
				// read as an inventory.
				//
				// Not the same sentence the grant gate produces, and it does not
				// need to be: this is only reachable *after* Reserve succeeded,
				// so the agent already holds a grant naming this profile and the
				// operator has already told it the name exists. The pairing that
				// has to be indistinguishable — unknown name versus ungranted
				// name — is both refused by the gate above, in the gate's own
				// words. TestAnUnknownProfileAndAnUngrantedOneLookTheSame pins
				// exactly that.
				return errResult(ungranted(c, profileName, opts.Agent)), nil
			}
			// After the gate, never before: a secret must not be fetched, and a
			// port-forward must not be opened into the operator's cluster, for
			// a call that is about to be refused.
			var verr2 *view.Error
			filled, verr2 = profile.Fill(ctx, profileName, conn, c, values, os.LookupEnv, opts.Secrets)
			if verr2 != nil {
				release()
				// Genericised the way Lookup's reason is, and for the same
				// reason one layer along: Fill's message names the store entry
				// the operator mapped ("reading prod-db-password for password"),
				// and builtin/kv.Reveal already refuses to list entry names to
				// anything that might be an agent. Handing one over in a failure
				// would undo that from the other side. The operator gets the
				// real message from `rta doctor` and from the same call at a
				// terminal.
				return errResult(view.Errorf("core.profile.secret.unavailable",
					"%s could not resolve a credential for profile %q", c.ID, profileName).
					WithHint("ask the operator to check `rta doctor`")), nil
			}
			// The forward, if this connection names a cluster. Last, because it
			// is the only step that opens something, and a refusal from any step
			// above must not have cost one.
			//
			// closeTunnel is not release's twin, though they sit two lines apart.
			// release refunds a use and must run only when the call failed; this
			// tears down the forward and must run always, which is why it is
			// deferred and release is not. A forward left open is a hole in a
			// cluster's network boundary with nobody watching.
			dialled, closeTunnel, verr3 := profile.Dial(ctx, profileName, conn, c, nil)
			defer closeTunnel()
			if verr3 != nil {
				release()
				// Genericised for the reason above it: a tunnel failure names the
				// operator's cluster, namespace and service, and an agent that can
				// read "service postgres not found in namespace databases" can map
				// the cluster one refusal at a time. The operator gets the real
				// message from the same call at a terminal and from `rta doctor`.
				return errResult(view.Errorf("core.profile.tunnel.unavailable",
					"%s could not reach the connection profile %q names", c.ID, profileName).
					WithHint("ask the operator to check `rta doctor`")), nil
			}
			for input, v := range dialled {
				filled[input] = v
			}
		}
		started := time.Now()
		v, err := c.Run(ctx, plugin.NewRequest(plugin.Resolve(c, plugin.Inputs{
			Caller:      values,
			Profile:     filled,
			ProfileName: profileName,
			Config:      opts.pluginConfig(c),
		}), false, true).WithSurface(plugin.SurfaceMCP).
			// The same guard the arguments went through, carried into the
			// handler for the paths it derives from them rather than
			// receives. checkPaths cannot see those: it walks the declared
			// inputs, and a repository reached by walking upward out of one
			// was never an argument.
			WithConfinement(opts.Paths.Check))
		rec.Millis = time.Since(started).Milliseconds()
		if err != nil {
			// No refund: the handler ran. A use used to come back on any
			// error, which made --max-uses and --rate mean nothing for the
			// capabilities they exist for — net.probe, net.port, http.*,
			// audit.web carry NeedsGrant because the failure *is* the
			// information ("connection refused" is a port map), and a
			// runaway loop is by definition one that is failing. What is
			// refunded is what never reached the handler: a profile that
			// would not resolve, a forward that would not open, a lock —
			// those releases sit above. A flaky capability burning a
			// one-time grant costs the operator a re-issue, which is the
			// honest outcome.
			ve := view.AsError(err, c.ID+".failed")
			// A handler's own policy gate — localOnly, humanOnly, a
			// credential-minting verb refusing agents — says so on the error
			// (view.Error.Refusal), and its no is a refusal in the ledger,
			// not an execution failure: an operator grepping outcome=refused
			// is asking what their agent tried that policy would not let it
			// do, and these gates are the exact half of that answer that used
			// to be filed under "the work broke". Auth deliberately keeps
			// whatever the call earned above: blocked means it never cleared
			// the authority gate, open or grant means authority allowed it
			// and the handler's own policy still said no — the pair tells a
			// reader where in the stack the refusal happened.
			if ve.Refusal {
				refusedBy(rec, ve)
			} else {
				failedBy(rec, ve)
			}
			return errResult(ve), nil
		}
		rec.Outcome = agentlog.Ran
		return viewResult(v)
	}
}

// takeProfile removes the host-owned "profile" argument from what the caller
// sent and returns it, refusing anything that is not a well-formed name.
//
// Refused rather than ignored: a caller that named a profile meant to reach
// somewhere other than the default, and silently running against the default
// instead is the one outcome nobody asked for.
func takeProfile(c plugin.Capability, values map[string]any, opts Options) (string, *view.Error) {
	// Only where the host owns the name. A capability with nothing a profile
	// could fill may legitimately declare its own input called "profile" —
	// builtin/grant does, because a profile name is the data it operates on —
	// and stripping that would leave the one command that issues profile
	// grants unable to name one. Capability.validate holds the other half of
	// this rule, so the two sets cannot drift apart.
	if !plugin.Profilable(c) {
		return "", nil
	}
	raw, given := values["profile"]
	delete(values, "profile")
	if !given {
		// R5. Once an operator has configured any profile for this namespace,
		// a call that names none is refused rather than run against the base
		// connection. Without it the feature is one-sided: an operator who
		// carefully grants "staging" leaves production sitting in plugins.pg:,
		// reachable by any agent with no grant at all, and adopting profiles
		// would have made their posture no better.
		//
		// Scoped to namespaces that actually have profiles, so it costs nothing
		// until an operator opts in by writing one, and it has no config key to
		// turn it off — a fail-closed rule with an off switch is a fail-open
		// rule with extra steps.
		//
		// **From the file, not from the startup snapshot.** Writing the first
		// profile for a namespace is the moment R5 starts protecting it, and it
		// is also the moment the operator believes they have protected it: the
		// base connection in `plugins.pg:` is production often enough that "I
		// have adopted profiles" and "production is still ungated" is the exact
		// pair this rule exists to prevent. Deciding from a snapshot meant the
		// rule switched on at the next restart, with nothing anywhere saying
		// so — the same defect as the connection stamp above, one field along.
		// Every other input to this decision is already read per call.
		if named := opts.profiles().ProfilesFor(plugin.Namespace(c.ID)); len(named) > 0 && plugin.Profilable(c) {
			return "", view.Errorf("core.profile.required",
				"%s has configured connections, so a call must name which one", c.ID).
				WithHint("ask the operator which profile to use and for a grant naming it")
		}
		return "", nil
	}
	name, ok := raw.(string)
	if !ok {
		return "", view.Errorf("core.profile.invalid", "profile must be a string")
	}
	// Trimmed, never case-folded. Folding would map "Prod" onto "prod" and
	// make a grant for one authorize a call naming the other; a name is either
	// the name or it is not.
	name = strings.TrimSpace(name)
	if name == "" {
		return "", view.Errorf("core.profile.invalid", "profile must not be empty")
	}
	// A reference, not just a name: `staging/analytics` addresses one of
	// several connections to the same plugin, and it must be expressible
	// here because a grant can name exactly that. Same grammar as the CLI
	// flag, so the string in the grant record, the call argument and the
	// audit line stay one string.
	if !config.ValidRef(name) {
		return "", view.Errorf("core.profile.invalid", "%q is not a valid profile reference", name)
	}
	return name, nil
}

// ungranted is the single refusal an agent gets for any profile it may not
// use, whatever the reason — it does not exist, it belongs to another plugin,
// it came from an untrusted file, or nobody has granted it.
//
// One sentence for four causes, on purpose. The name the caller supplied is
// echoed so a person reading the transcript can see a typo in one line, and
// the command they would have to run is spelled out, because the agent cannot
// issue a grant itself and the whole exchange terminates at a human anyway.
func ungranted(c plugin.Capability, name, agent string) *view.Error {
	cmd := "rta grant allow " + plugin.Namespace(c.ID) + " --profile " + name
	if agent != "" {
		cmd += " --agent " + agent
	}
	return view.Errorf("core.grant.required",
		"agents may not use %s on profile %q without a person's consent", c.ID, name).
		WithHint("ask the operator to run: " + cmd + " --ttl 15m")
}

// ValidateArgs checks every argument the caller actually supplied
// against its declared Field — type, and closed-set membership when the
// field declares Options — and refuses any name the schema does not offer.
// checkPaths confines every caller-supplied path argument to the guard.
//
// The hook is Field.Type == Path, which is what makes it worth having had a
// closed and mandatory type: the declaration already says which
// inputs name files, so the host does not have to guess from the value. The
// alternative — treating any argument that looks absolute as a path — was
// tried and is wrong: base64's alphabet contains "/", so `codec.b64` decoding
// a JPEG ("/9j/4AAQ...") would be refused as an escape attempt.
//
// That hook is also the limit of what this can see. A built-in that opens a
// path from a field declared String is outside it, which is why cert's file
// input was changed to say what it is rather than guarded as a special case:
// a control that needs a list of exceptions is a control with a list of holes.
// TestEveryPathInputIsConfined walks the catalogue so a new Path input is
// covered the day it lands.
func checkPaths(c plugin.Capability, values map[string]any, g *pathguard.Guard) *view.Error {
	if g == nil {
		return nil
	}
	for _, f := range c.Inputs {
		if f.Type != plugin.Path || f.Local {
			continue
		}
		v, given := values[f.Name]
		if !given {
			continue
		}
		s, ok := v.(string)
		if !ok {
			// Refused, not skipped. A `continue` here is a silent pass in the
			// one function whose failure mode must be a refusal — it says
			// "the type check has already refused this", which is true for a
			// declared Path and is a promise about a different function. If
			// that ever stops holding, this is the line that turns it into an
			// unconfined read rather than an error.
			return view.Errorf("core.mcp.path.unresolvable",
				"%s: expected a path, got %s", f.Name, toolcall.JSONKind(v))
		}
		resolved, verr := g.Check(f.Name, s)
		if verr != nil {
			return verr
		}
		// Substituted, not merely approved. The guard resolves the caller's
		// string — tilde, symlinks, "..", the lot — decides on the result,
		// and this used to hand the *original* spelling to the handler. Two
		// readers of one string, and whether they agreed was luck: builtin/fs
		// happens to call filepath.Abs and therefore Clean the same way the
		// guard did, so it survived the ".." escape this accompanies, while
		// builtin/net opens the raw value and did not.
		//
		// Writing the judged path back makes them the same string by
		// construction. Worth doing on its own terms and not only as part of
		// that fix: it is what turns the next resolve() bug from an escape
		// into a handler opening a path that is not there.
		values[f.Name] = resolved
	}
	return nil
}

// viewResult encodes a view as both text (JSON envelope) and structured
// content. Redacted fields are masked here too — an MCP caller reaches this
// path without a human present, so it gets the same masking guarantee as
// every other renderer (pkg/view.Redact).
// viewResult encodes a result for a model.
//
// textclean.Model, not only Redact. Redact answers "may the caller see this
// value"; it says nothing about what the value does when a model reads it. A
// result is per-call, unbounded and attacker-influenced — `http.get` returns
// an arbitrary internet body straight into a model's context, and that is true
// today with no plugin installed — so the same neutralising the terminal
// renderers do is owed here, plus the invisible characters a terminal does not
// care about and a model reads as text.
//
// The contract used to say json was "lossless and safe at once, and it
// is what the MCP bridge encodes". The first half is true against a terminal,
// because the encoder escapes the byte. It was never true against a model,
// which reads the decoded string.
func viewResult(v view.View) (*sdk.CallToolResult, error) {
	m, err := view.ToMap(view.Redact(view.MapStrings(v, textclean.Model)))
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: string(raw)}},
		StructuredContent: m,
	}, nil
}

func errResult(e *view.Error) *sdk.CallToolResult {
	// AsError puts a foreign error's own text into Message, so an error is as
	// much a channel from elsewhere as a result body is.
	raw, _ := json.Marshal(view.Envelope{View: view.MapErrorStrings(e, textclean.Model)})
	return &sdk.CallToolResult{
		IsError: true,
		Content: []sdk.Content{&sdk.TextContent{Text: string(raw)}},
	}
}
