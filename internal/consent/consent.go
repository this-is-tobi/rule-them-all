// Package consent parks an agent's call and waits for a person to answer it.
//
// The shape is two files in a directory rather than a daemon or a socket,
// because the two sides are two processes that never meet: `rta mcp serve`
// is a subprocess of somebody's editor, and the operator is at a terminal
// somewhere else. A request file is written by the asking process and read
// by whatever the operator is using; a decision file is written by the
// operator's process and polled for by the asker.
//
// **The request is a display; the digest is the binding.** What the parked
// call waits for is a decision naming the digest of the exact call —
// capability, scopes, profile and arguments, canonically encoded — which
// the asking process computes itself and compares. A local attacker who
// rewrites a request file so it reads `sys.cpu` while a `kv.get` waits
// changes only what the operator is shown: their approval then carries the
// displayed call's digest, no waiting call matches it, and nothing runs.
//
// **That last sentence is a property of the deciding side, not a wish**, and
// it needs one thing to be true: the digest that goes into a decision has to
// be *derived from what was displayed*, never copied out of the file. The
// first version copied it, and so the sentence above was false — rewriting
// `capability` while leaving the digest alone showed the operator `sys.cpu`,
// bound their approval to `kv.get db-password`, and ran the second one. Every
// displayed field worked that way. Request.Honest is the check, applied in
// the one walk every surface reads the queue through (Scan), and it holds
// only because the digest's inputs are exactly the fields a person reads.
// A request that does not agree with itself is kept off the queue and
// counted, because it was written by something that is not rta.
//
// **Decisions are sealed; requests are not.** A decision is an
// authorization, and an unsealed one rebuilds exactly the hole the grant seal
// closed for grants — a confined plugin, denied every read of the data
// directory and never denied a write, could drop an approval for itself. A
// request carries no authority, so the worst a forged one achieves is a
// question the operator did not expect, whose answer authorizes nothing.
package consent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/this-is-tobi/rta/internal/atomicfile"
	"github.com/this-is-tobi/rta/internal/filelock"
	"github.com/this-is-tobi/rta/internal/paths"
	"github.com/this-is-tobi/rta/internal/seal"
)

const (
	dir     = "agent-requests"
	keyFile = "agent-consent.key"
	// pollEvery is how often a parked call looks for its answer. Fast
	// enough that saying yes feels immediate, slow enough to be free.
	pollEvery = 200 * time.Millisecond
	// DefaultWait is how long a parked call waits by default. Under most
	// MCP clients' own timeouts, and long enough to switch windows and read
	// a line.
	DefaultWait = 90 * time.Second
	// MaxWait bounds --consent-wait: past a couple of minutes the agent's
	// own client has usually given up, and a call nobody is waiting for is
	// a lock on the operator's attention with nothing at the other end.
	MaxWait = 10 * time.Minute
	// MaxParked bounds how many questions can be waiting at once.
	//
	// Consent fatigue is *the* attack on any ask-the-human control, and it
	// needs no cleverness to mount: a model that retries a refused call in a
	// loop produces the same flood as one deliberately burying the request
	// that matters. Past a handful, a list of decisions stops being read and
	// starts being cleared, and every answer after that is a reflex. rta
	// would rather refuse the ninth call outright — exactly the refusal that
	// would have happened with no consent at all — than ask a question that
	// will be answered without being read.
	//
	// It bounds the queue and not the caller, because there is no caller to
	// bound: several `rta mcp serve` processes, one per editor, share this
	// directory and the operator has one attention between them.
	MaxParked = 8
)

// ErrTooMany means the queue of unanswered questions is full.
var ErrTooMany = errors.New("too many requests are already waiting")

// Dir is where requests and decisions live.
func Dir() string { return filepath.Join(paths.Data(), dir) }

// Request is one parked call, as written for the operator to read.
type Request struct {
	ID string `json:"id"`
	// Digest binds a decision to this exact call. See the package comment:
	// everything else in this struct is display.
	Digest  string   `json:"digest"`
	Cap     string   `json:"capability"`
	Safety  string   `json:"safety"`
	Scopes  []string `json:"scopes,omitempty"`
	Profile string   `json:"profile,omitempty"`
	// Pin fingerprints the connection the profile named when this call was
	// made, carried so that answering with --ttl can issue a grant bound to
	// that connection rather than to the name. A profiled grant with no pin
	// covers nothing (internal/grant: fail-closed), so without this the
	// convenience would silently issue a dead grant.
	Pin string `json:"pin,omitempty"`
	// Agent is the name the server that took this call was launched under.
	// Carried for the same two reasons Pin is: the operator has to see which
	// of their agents is asking before they answer, and answering with --ttl
	// must issue a grant that names that agent — an agent-less grant would
	// authorize the *unnamed* server and not the one that asked.
	Agent string         `json:"agent,omitempty"`
	Args  map[string]any `json:"args,omitempty"`
	// Preview is what the capability said it would do, from its own
	// --dry-run, so the operator approves an outcome rather than an
	// intention. Display like everything else here: it is the most
	// persuasive thing in the file and it is still not the binding.
	Preview string `json:"preview,omitempty"`
	// Why is the gate's own refusal, so the operator reads what would have
	// happened rather than only what is wanted.
	Why      string    `json:"why,omitempty"`
	AskedAt  time.Time `json:"asked_at"`
	Deadline time.Time `json:"deadline"`
}

// Call is what the asking side knows about the call it wants to make.
type Call struct {
	Cap     string
	Safety  string
	Scopes  []string
	Profile string
	Pin     string
	Agent   string
	Args    map[string]any
	Why     string
	Preview string
}

// Call reconstructs the call this request displays, so that the digest can be
// recomputed from the fields a person actually reads.
//
// **This is what makes the package comment's claim true**, and for a while it
// was missing. The claim is that rewriting a request changes only what the
// operator is shown, because their approval would then carry the *displayed*
// call's digest and no waiting call would match it. Decide did not derive a
// digest at all — it copied the one out of the file it was handed — so
// rewriting `capability` to `sys.cpu` and leaving the digest alone produced a
// prompt reading `sys.cpu`, an approval binding `kv.get db-password`, and the
// second one running. Every displayed field was rewritable that way, tested
// one at a time in tamper_test.go.
//
// The digest is unkeyed and its inputs are exactly these six fields, so
// deriving it here needs no secret and no second mechanism — the check is
// that the file agrees with itself.
func (r Request) Call() Call {
	return Call{
		Cap: r.Cap, Safety: r.Safety, Scopes: r.Scopes,
		Profile: r.Profile, Pin: r.Pin, Agent: r.Agent, Args: r.Args,
	}
}

// Honest reports whether this request's display and its digest describe the
// same call.
//
// Why and Preview are not in the digest and so are not checked here, which is
// deliberate and is the reason this is a recomputation rather than a seal:
// both are prose *about* the call written by the asking process, and a
// mechanism that refused a request over its wording would break the queue
// every time a sentence changed. Rewriting them still misleads a reader, and
// that is the bound already stated — what it must not do is change
// what runs, and it cannot, because neither reaches the call.
//
// A request with no digest at all is not honest. That is the shape a blind
// writer produces most cheaply, and treating an absent binding as a passing
// one would make the check opt-out.
func (r Request) Honest() bool {
	return r.Digest != "" && r.Call().Digest() == r.Digest
}

// Digest is the binding: a hash over what a person is being asked to
// approve, computed identically on both sides.
//
// Unkeyed on purpose. It is not a secret and it proves nothing about who
// wrote it — it is an equality check the waiting process performs against a
// value it derived itself, which is what makes a rewritten display
// harmless. The authority in this package is the decision's seal.
//
// Why nor Preview are in it, and that is the same rule stated twice: both
// are prose *about* the call rather than part of it, and both are what the
// operator actually reads. A local attacker who rewrites either changes
// what somebody is told and not what they authorize — their approval still
// names the call that is really waiting, and the call that is really
// waiting is the one that runs or does not.
func (c Call) Digest() string {
	// Sorted keys and a fixed separator, so two encodings of the same call
	// cannot differ: Go's map iteration order would otherwise make the
	// digest depend on nothing at all.
	h := sha256.New()
	// Agent is inside the digest because it is part of the call rather than
	// prose about it: rewriting it in the parked file would show the operator
	// one agent's name and bind another's request. That is exactly the rewrite
	// this digest exists to make harmless.
	fmt.Fprintf(h, "cap:%s\nsafety:%s\nprofile:%s\npin:%s\nagent:%s\n",
		c.Cap, c.Safety, c.Profile, c.Pin, c.Agent)
	scopes := append([]string(nil), c.Scopes...)
	sort.Strings(scopes)
	for _, s := range scopes {
		fmt.Fprintf(h, "scope:%d:%s\n", len(s), s)
	}
	keys := make([]string, 0, len(c.Args))
	for k := range c.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, err := json.Marshal(c.Args[k])
		if err != nil {
			v = []byte(fmt.Sprintf("%q", fmt.Sprint(c.Args[k])))
		}
		fmt.Fprintf(h, "arg:%d:%s=%d:%s\n", len(k), k, len(v), v)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// decision is the sealed answer.
type decision struct {
	ID     string    `json:"id"`
	Digest string    `json:"digest"`
	Allow  bool      `json:"allow"`
	At     time.Time `json:"at"`
	// By names the surface that answered, for the ledger.
	By   string `json:"by,omitempty"`
	Seal string `json:"seal"`
}

func requestPath(id string) string  { return filepath.Join(Dir(), id+".request.json") }
func decisionPath(id string) string { return filepath.Join(Dir(), id+".decision.json") }

// Parked is a request that has been written and is waiting for an answer.
type Parked struct {
	Request Request
}

// Ask writes the request. The caller must Close it.
func Ask(c Call, wait time.Duration) (*Parked, error) {
	if wait <= 0 {
		wait = DefaultWait
	}
	if wait > MaxWait {
		wait = MaxWait
	}
	// Counting and writing happen under one lock, and that is not
	// bookkeeping tidiness. A first version counted first and wrote after,
	// with a comment calling the cap "approximate under a race"; ten
	// pipelined `tools/call` requests then parked all ten, because the
	// go-sdk dispatches each in its own goroutine, all ten read the same
	// empty directory and all ten wrote. A burst is precisely what the cap
	// exists to stop, so a bound that only holds when calls arrive one at a
	// time is not a bound at all — the same lesson grant.Reserve learned
	// against a MaxUses:1 grant, one mechanism along. The lock is shared
	// across processes for the same reason the queue is: several servers,
	// one operator's attention.
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return nil, err
	}
	release, err := filelock.Acquire(Dir()+".lock", 5*time.Second, 5*time.Millisecond, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("the request queue is busy: %w", err)
	}
	defer release()

	// Only requests something is still waiting on: an expired one is litter
	// Pending sweeps, not a question competing for anybody's attention.
	waiting, err := Pending()
	if err != nil {
		return nil, err
	}
	live := 0
	for _, r := range waiting {
		if time.Now().Before(r.Deadline) {
			live++
		}
	}
	if live >= MaxParked {
		return nil, ErrTooMany
	}
	id, err := freshID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	req := Request{
		ID: id, Digest: c.Digest(), Cap: c.Cap, Safety: c.Safety,
		Scopes: c.Scopes, Profile: c.Profile, Pin: c.Pin, Agent: c.Agent, Args: c.Args, Why: c.Why,
		Preview: c.Preview,
		AskedAt: now.UTC().Truncate(time.Second),
		// Truncated too, so the deadline an operator reads and the one this
		// process enforces are the same second.
		Deadline: now.Add(wait).UTC().Truncate(time.Second),
	}
	body, err := fit(&req)
	if err != nil {
		return nil, err
	}
	if err := atomicfile.Write(requestPath(id), body, 0o600); err != nil {
		return nil, err
	}
	return &Parked{Request: req}, nil
}

// ErrTooBig means the call cannot be described inside one request file.
var ErrTooBig = errors.New("the call is too large to park")

// fit encodes the request, keeping it inside what the reader will accept.
//
// The reader is bounded (maxRequest) because this directory is writable by
// something other than rta. That bound applies to rta's own files too, so
// without this it could write a request larger than it will read back: a
// parked call that no surface lists and nobody can answer, waiting out its
// deadline for an operator who was never shown it. No attacker needed — a
// preview is a capability's own dry-run output, and nothing caps how much of
// that there is.
//
// **Prose is trimmed and the call is refused**, which is the same split the
// digest already makes. Why and Preview describe the call without being part
// of it, so shortening them costs a reader some words and changes nothing
// about what is authorized — the request still binds exactly what it bound.
// Everything else *is* the call, and a call whose arguments will not fit on
// a screen is not one an operator can meaningfully consent to, so it gets
// ErrTooBig and the caller falls back to the refusal that would have happened
// with no consent at all. Showing a fraction of what is being approved would
// be worse than showing nothing, because it would be believed.
func fit(req *Request) ([]byte, error) {
	body, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(body) <= maxRequest {
		return body, nil
	}
	req.Preview, req.Why = "", ""
	if body, err = json.MarshalIndent(req, "", "  "); err != nil {
		return nil, err
	}
	if len(body) > maxRequest {
		return nil, fmt.Errorf("%w: %d bytes of arguments is more than a person can be shown",
			ErrTooBig, len(body))
	}
	// Said rather than silently dropped: the operator is about to decide with
	// less in front of them than rta had.
	req.Why = "the description of this call was too long to show, so it was left out — " +
		"the capability and its arguments above are the whole of what you are approving"
	if body, err = json.MarshalIndent(req, "", "  "); err != nil {
		return nil, err
	}
	// The placeholder just re-added is itself bytes, and the check two steps
	// up never accounted for them: a body that landed just under maxRequest
	// with Preview/Why stripped can land back over it once this sentence
	// goes back in. Unchecked, that body would still be written — by
	// readRequestFile's own bound, a file rta's own writer produced and
	// could never read back.
	if len(body) > maxRequest {
		return nil, fmt.Errorf("%w: %d bytes of arguments is more than a person can be shown",
			ErrTooBig, len(body))
	}
	return body, nil
}

// Close removes the request and any answer to it. Always call it: a request
// left behind is a question the operator can still answer, for a call that
// stopped waiting long ago.
func (p *Parked) Close() {
	if p == nil {
		return
	}
	_ = os.Remove(requestPath(p.Request.ID))
	_ = os.Remove(decisionPath(p.Request.ID))
}

// Answer is the outcome of waiting.
type Answer struct {
	Allowed bool
	// By is the measured origin of the decision, carried into the record
	// so an approval names who gave it rather than only that somebody did.
	By string
	// Answered is false when nobody replied before the deadline — which is
	// not a no from anybody, and the caller reports it as the refusal that
	// would have happened without consent at all.
	Answered bool
}

// Wait blocks until the request is answered, the deadline passes, or ctx
// ends.
func (p *Parked) Wait(ctx context.Context) Answer {
	if p == nil {
		return Answer{}
	}
	key, err := seal.Key(keyFile, false)
	keyMissing := errors.Is(err, seal.ErrMissing)
	if err != nil && !keyMissing {
		return Answer{}
	}
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		if keyMissing {
			// No key yet means nothing has ever answered on this machine;
			// look again each tick, because the first `rta agent allow`
			// creates it.
			if k, kerr := seal.Key(keyFile, false); kerr == nil {
				key, keyMissing = k, false
			}
		}
		if !keyMissing {
			if d, ok := readDecision(key, p.Request.ID); ok && d.Digest == p.Request.Digest {
				return Answer{Allowed: d.Allow, Answered: true, By: d.By}
			}
		}
		select {
		case <-ctx.Done():
			return Answer{}
		case <-ticker.C:
			if time.Now().After(p.Request.Deadline) {
				return Answer{}
			}
		}
	}
}

// readDecision returns a verified decision, or ok=false.
//
// An unverifiable decision is treated as absent rather than as a denial:
// the file is the one thing here an attacker might forge, and "ignore it
// and keep waiting" ends in the same refusal a denial would produce,
// without letting a forged file cut short a question the operator is in the
// middle of answering.
func readDecision(key []byte, id string) (decision, bool) {
	raw, err := atomicfile.ReadCapped(decisionPath(id), maxDecision)
	if err != nil {
		return decision{}, false
	}
	var d decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return decision{}, false
	}
	want, err := sealOf(key, d)
	if err != nil || !seal.Equal(d.Seal, want) {
		return decision{}, false
	}
	if d.ID != id {
		return decision{}, false
	}
	return d, true
}

func sealOf(key []byte, d decision) (string, error) {
	d.Seal = ""
	body, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return seal.MAC(key, body), nil
}

// Queue is what is waiting, and what was found to be lying about itself.
type Queue struct {
	// Waiting are the requests a person may read and answer, oldest first.
	Waiting []Request
	// Tampered are the ids of requests whose display does not match their
	// digest. They are kept off Waiting and counted here rather than
	// silently dropped: a request that does not agree with itself was
	// written by something other than the process that parked the call, and
	// that is the one event on this queue worth interrupting somebody for.
	Tampered []string
}

// Scan lists the queue and reports what did not survive reading.
func Scan() (Queue, error) {
	var q Queue
	entries, err := os.ReadDir(Dir())
	if errors.Is(err, os.ErrNotExist) {
		return q, nil
	}
	if err != nil {
		return q, err
	}
	// Which requests exist, before judging anything — the walk below also
	// sweeps decision files whose request is gone, and that pairing has to
	// be read off one directory snapshot.
	requests := map[string]bool{}
	for _, e := range entries {
		if name := e.Name(); strings.HasSuffix(name, ".request.json") {
			requests[strings.TrimSuffix(name, ".request.json")] = true
		}
	}
	now := time.Now()
	for _, e := range entries {
		name := e.Name()
		// A decision without its request is an orphan: decide racing
		// Parked.Close can write the answer after the asker stopped waiting
		// and removed the question, and nothing else ever looks at the file
		// again — Close removes by the id it holds, and every other sweep
		// here starts from a request. Left behind, it is also the one input
		// to a stale-approval replay: ids are 32-bit, so a future Ask can
		// mint this id again, and a byte-identical call under it would find
		// an answer nobody gave *this* asking. Ask lists the queue through
		// this walk, under the queue lock, before minting an id — so
		// sweeping here is what makes that reuse meet an empty slot instead.
		if id, ok := strings.CutSuffix(name, ".decision.json"); ok && !requests[id] {
			_ = os.Remove(decisionPath(id))
			continue
		}
		if !strings.HasSuffix(name, ".request.json") {
			continue
		}
		id := strings.TrimSuffix(name, ".request.json")
		r, ok := load(id)
		if !ok {
			// Nothing here will ever become a valid request: load fails only
			// for a parse error, an id that does not match its own filename,
			// or a file bigger than rta's own writer ever produces (all of
			// which land only through this directory's other writer — see
			// Honest's doc comment — since Ask writes atomically and this
			// process's own files always parse) or a file that is simply
			// gone by the time this got to it. A deadline is a property of a
			// request Scan could actually read; there is no reason to wait
			// on one for bytes that were never a request at all, and no
			// sweep elsewhere in this package will ever reach these — the
			// deadline sweep two lines below runs only for entries that
			// parsed.
			_ = os.Remove(requestPath(id))
			_ = os.Remove(decisionPath(id))
			continue
		}
		// A minute past the deadline the asker has certainly stopped
		// waiting; before that, leave it — an answer arriving on the last
		// second is still an answer. Ahead of the honesty check, so a
		// doctored request is still swept once it is stale rather than
		// accumulating as permanent litter.
		if now.After(r.Deadline.Add(time.Minute)) {
			_ = os.Remove(requestPath(id))
			_ = os.Remove(decisionPath(id))
			continue
		}
		// Filtered here, in the one function every surface reads the queue
		// through, rather than checked again in each of them. `agent
		// pending`, `agent show`, the TUI, tab completion and Decide itself
		// all arrive via this walk, and a rule enforced at the reads instead
		// would hold for exactly as long as nobody adds a sixth.
		if !r.Honest() {
			q.Tampered = append(q.Tampered, id)
			continue
		}
		q.Waiting = append(q.Waiting, r)
	}
	sort.Slice(q.Waiting, func(i, j int) bool { return q.Waiting[i].AskedAt.Before(q.Waiting[j].AskedAt) })
	sort.Strings(q.Tampered)
	return q, nil
}

// maxRequest bounds one request file.
//
// The file is written by rta and read by rta, and in between it sits in a
// directory whose whole threat model is that somebody else can write there.
// An unbounded ReadFile on an attacker-chosen file is a way to take the
// operator's terminal — or the server that walks this queue before every
// parked call — out with a single large write. Generous next to a real
// request, which is a few hundred bytes plus a preview.
const maxRequest = 256 << 10

// maxDecision bounds one decision file, for the reason above and one more:
// a decision is the *authorization*, where a request is only the display of
// one, and it is read on a 200ms poll for as long as a call stays parked —
// so the unbounded read this replaces was the cheaper of the two to trigger
// and the more valuable to hit. Decide writes a couple of hundred bytes;
// 4 KiB is far past anything real and still nothing to load.
const maxDecision = 4 << 10

// load reads and parses one request by id, without judging it.
//
// The honesty check is the caller's, deliberately: the two callers want
// different things from a request that does not agree with itself — Scan
// counts it, Decide refuses it by name — and a loader that dropped it would
// leave both of them unable to tell it apart from an id that expired.
func load(id string) (Request, bool) {
	raw, err := readRequestFile(id)
	if err != nil {
		return Request{}, false
	}
	var r Request
	if err := json.Unmarshal(raw, &r); err != nil || r.ID != id {
		return Request{}, false
	}
	return r, true
}

// readRequestFile reads one request, refusing one too big to be genuine.
func readRequestFile(id string) ([]byte, error) {
	return atomicfile.ReadCapped(requestPath(id), maxRequest)
}

// Pending lists the requests waiting right now, oldest first, sweeping any
// whose deadline has long passed.
//
// The sweep is here rather than on a timer because this is the only code
// that has a reason to look: a request whose asker has gone is litter, and
// litter in a list of things awaiting your decision is how the list stops
// being read.
func Pending() ([]Request, error) {
	q, err := Scan()
	return q.Waiting, err
}

// Find returns one pending request by id.
func Find(id string) (Request, bool) {
	all, err := Pending()
	if err != nil {
		return Request{}, false
	}
	for _, r := range all {
		if r.ID == id {
			return r, true
		}
	}
	return Request{}, false
}

// Decide writes the sealed answer to one request.
//
// by names the surface that answered, for the ledger. Only human surfaces
// ever call this — builtin/agent refuses SurfaceMCP outright — and that
// refusal is the mechanism, not this parameter.
func Decide(id string, allow bool, by string) error {
	return decide(id, "", allow, by)
}

// DecideBound is Decide with one more precondition: the request on disk
// must still carry the digest the answerer read. The local flow can live
// without it because display and decision are seconds apart on one
// machine; a remote answer's display crossed a network and a queue that
// something else can write, so the digest of what was shown travels with
// the answer and is compared here, against the same load the decision is
// minted from — checking it any earlier would leave a gap between the
// check and the seal for the file to be swapped in.
func DecideBound(id, digest string, allow bool, by string) error {
	if digest == "" {
		// An empty binding must not degrade into Decide's trust-the-disk
		// behaviour silently: the one caller of this function always has a
		// digest, so an empty one is a bug upstream, not a choice.
		return fmt.Errorf("an answer to request %q arrived with no digest to bind it", id)
	}
	return decide(id, digest, allow, by)
}

func decide(id, digest string, allow bool, by string) error {
	// Read directly rather than through Find, and check honesty here.
	//
	// Find filters already, so routing through it would be shorter and would
	// leave this function's guarantee borrowed from a display helper — true
	// only for as long as nobody loosens a queue listing. This is the one
	// place an approval is minted, so it establishes its own precondition:
	// what is sealed below is a digest recomputed from fields this function
	// has itself confirmed match the one on disk.
	req, ok := load(id)
	if !ok {
		return fmt.Errorf("no request %q is waiting", id)
	}
	// Two ways to be unanswerable, and they are not the same news. A request
	// that is not there expired or was answered already; one that is there and
	// does not match its digest was rewritten under the operator, and telling
	// them "nothing is waiting" would file an attack on their consent prompt
	// under housekeeping.
	if !req.Honest() {
		return fmt.Errorf("request %q does not describe the call it is bound to, so it "+
			"cannot be answered — something rewrote it after rta parked it", id)
	}
	if digest != "" && req.Digest != digest {
		// Honest on its own only proves the file agrees with itself; a swap
		// for a *different* honest request under the same id passes it. The
		// answerer's digest is what pins the file to the call they read.
		return fmt.Errorf("request %q no longer describes the call that was read before answering — "+
			"it was replaced after being displayed, and the answer given binds nothing that is waiting", id)
	}
	key, err := seal.Key(keyFile, true)
	if err != nil {
		return fmt.Errorf("consent key: %w", err)
	}
	d := decision{
		// Derived from what was displayed, never copied from the file. Equal
		// to req.Digest by the check above — and written this way because the
		// version that copied it is the one that shipped the hole: a line
		// reading "trust the file" is the mistake, whether or not it is
		// currently reachable.
		ID: id, Digest: req.Call().Digest(), Allow: allow,
		At: time.Now().UTC().Truncate(time.Second), By: by,
	}
	if d.Seal, err = sealOf(key, d); err != nil {
		return err
	}
	body, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(decisionPath(id), body, 0o600)
}

// newID is short enough to type and wide enough not to collide.
func newID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// freshID mints an id no parked request already holds. 32 bits make a
// collision unlikely, not impossible, and Ask would otherwise overwrite a
// live request in place — the first call's asker left polling a file that
// now describes somebody else's question. The caller holds the queue
// lock, so check-then-write cannot race another Ask; the bound exists
// only so a broken filesystem fails as an error instead of a spin.
func freshID() (string, error) {
	for range 4 {
		id, err := newID()
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(requestPath(id)); errors.Is(err, os.ErrNotExist) {
			return id, nil
		}
	}
	return "", errors.New("could not mint an unused request id")
}
