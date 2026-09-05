package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/this-is-tobi/rta/internal/agentlog"
	"github.com/this-is-tobi/rta/internal/consent"
	"github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/notify"
	"github.com/this-is-tobi/rta/internal/textclean"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// The two halves of the agent record that live on this surface: what gets written
// down about a call, and what happens when the gate refuses one and there
// is somebody who could say yes.

// refusedBy marks the entry refused, naming the gate in rta's own
// vocabulary — the code and the message in their own fields, because the
// code is what a later reader (or a SIEM rule) matches exactly and the
// message is what a person understands, and gluing them into one string
// made matching the stable half depend on the wording of the other.
func refusedBy(e *agentlog.Entry, verr *view.Error) {
	if e == nil || verr == nil {
		return
	}
	e.Outcome, e.Code, e.Reason = agentlog.Refused, cut(verr.Code, maxCode), cut(verr.Message, maxReason)
}

// maxReason and maxCode bound what a handler's error may put in a row. A
// message that echoes an argument echoes whatever size the caller chose,
// and the record must stay readable at its end whatever a caller sends.
const (
	maxReason = 1 << 10
	maxCode   = 128
)

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s + "…"
}

// failedBy is refusedBy's sibling for the other outcome: the call was
// allowed and the work broke.
func failedBy(e *agentlog.Entry, verr *view.Error) {
	if e == nil || verr == nil {
		return
	}
	e.Outcome, e.Code, e.Reason = agentlog.Failed, cut(verr.Code, maxCode), cut(verr.Message, maxReason)
}

// maxClientName bounds what a caller may write into every one of its own
// ledger rows. Long enough for "some-editor-extension 1.2.3-beta.4", short
// enough that a client cannot inflate the operator's record — the string is
// repeated on every entry, so an unbounded one is a disk-filling primitive
// handed out at the handshake.
const maxClientName = 64

// clientName is the name and version the caller announced for itself, cleaned
// and bounded.
//
// **Everything about this string is the client's claim**, so it is treated the
// way every other view of foreign data is: run through textclean.Terminal,
// because it is read back by a person on a terminal and an MCP client is free
// to call itself "\x1b]8;;http://evil\x07vault\x1b]8;;\x07". Truncated rather
// than refused — a hostile clientInfo is not a reason to fail a call, it is a
// reason for the record to be readable afterwards.
//
// It authorizes nothing. See agentlog.Entry.Client.
func clientName(req *sdk.CallToolRequest) string { return implementationName(req.ClientInfo()) }

// implementationName is the client's announced name and version, cleaned for
// a terminal and bounded, from the handshake or from a call.
func implementationName(info *sdk.Implementation) string {
	if info == nil {
		return ""
	}
	name := textclean.Terminal(strings.TrimSpace(info.Name))
	if v := textclean.Terminal(strings.TrimSpace(info.Version)); name != "" && v != "" {
		name += " " + v
	}
	if len(name) > maxClientName {
		// Cut on a rune boundary: a byte-slice through a multi-byte character
		// puts invalid UTF-8 into a sealed file, where it stays forever.
		for len(name) > maxClientName {
			_, size := utf8.DecodeLastRuneInString(name)
			name = name[:len(name)-size]
		}
		name += "…"
	}
	return name
}

// maxCredentialName mirrors maxClientName: a token's own label crosses a
// trust boundary (an operator's file over the static-token path, an external
// IdP's subject claim over the OIDC one) into a sealed, permanent log, so it
// gets the same bound rather than a second, unexamined assumption that it is
// well-behaved.
const maxCredentialName = 64

// credentialSuffixLen is how many bytes of a hash of the *full* value are
// appended, as hex, when credentialName has to cut a name down to
// maxCredentialName. A plain byte-slice truncation — the same one
// clientName uses — is fine for a client's self-reported display name,
// which authorizes nothing; it is not fine here, where two different real
// identities (most plausibly two long OIDC subjects) sharing the same
// 64-byte prefix would otherwise be written into the sealed audit trail as
// the byte-identical Credential value, silently merging two people into one
// row of the record.
const credentialSuffixLen = 5

// credentialName is which bearer credential authenticated this call, over
// HTTP — a static token's label or an OIDC subject — or "" over stdio, where
// there is no bearer identity on the wire to name. Neither built-in verifier
// can hand back an empty UserID for an authenticated call (LoadTokenFile
// rejects an empty label, OIDCVerifier rejects an empty --oidc-subject), so
// "" here means stdio and nothing else. See agentlog.Entry.Credential.
func credentialName(ctx context.Context) string {
	info := auth.TokenInfoFromContext(ctx)
	if info == nil || info.UserID == "" {
		return ""
	}
	name := textclean.Terminal(strings.TrimSpace(info.UserID))
	if len(name) <= maxCredentialName {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	suffix := "~" + hex.EncodeToString(sum[:credentialSuffixLen])
	budget := maxCredentialName - len(suffix)
	for len(name) > budget {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name + suffix
}

// record writes one entry, and never fails a call over it.
//
// A call that ran and was not recorded leaves a gap the chain itself shows
// — the sequence numbers skip — whereas a call refused because the ledger
// could not be written would be rta breaking the operator's tooling to
// protect its own bookkeeping. The note goes to stderr, which under
// `mcp serve` is the server's log rather than the agent's channel.
func record(e agentlog.Entry) {
	if err := agentlog.Append(e); err != nil {
		fmt.Fprintln(os.Stderr, "rta: could not record this call:", err)
	}
}

// auditArgs is what the ledger and the consent prompt are allowed to show
// of a caller's arguments.
//
// Two rules, both non-negotiable. A Secret input is masked — a credential
// that reaches a log file has leaked exactly as thoroughly as one that
// reaches a model, and this file is meant to be read. And every string is
// put through textclean.Model, the same treatment results already get: an
// argument is attacker-influenced text that will be read back by a person
// in a terminal and, sooner or later, by an agent grepping the ledger.
func auditArgs(c plugin.Capability, values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	secret := make(map[string]bool, len(c.Inputs))
	for _, f := range c.Inputs {
		if f.Type.Sensitive() {
			secret[f.Name] = true
		}
	}
	out := make(map[string]any, len(values))
	for k, v := range values {
		switch {
		case secret[k]:
			out[k] = view.Mask
		default:
			out[k] = cleanValue(v)
		}
	}
	return out
}

func cleanValue(v any) any {
	switch t := v.(type) {
	case string:
		return textclean.Model(t)
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = textclean.Model(s)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = cleanValue(e)
		}
		return out
	default:
		return v
	}
}

// askConsent parks a refused call and waits for the operator's answer.
//
// It returns (allowed, asked). asked is false when this call was never a
// question — consent is off, the refusal was not about a missing grant, or
// the session fence forbids asking — so the caller knows to record the
// gate's own refusal rather than a decision nobody made.
func askConsent(ctx context.Context, c plugin.Capability, opts Options, values map[string]any,
	profileName string, verr *view.Error, rec *agentlog.Entry) (allowed, asked bool) {
	if !opts.Consent || verr == nil {
		return false, false
	}
	// Only the missing-grant refusal is a question. Everything else the
	// gate can say — a malformed argument, a path outside the root — is a
	// statement about the call rather than about permission, and asking a
	// person to approve a call that is wrong on its own terms would teach
	// them to approve without reading.
	if verr.Code != "core.grant.required" {
		return false, false
	}
	// The session fence is not negotiable per call: while the
	// operator works in one environment, agents are in that environment and
	// nowhere else — the fence exists so this decision is NOT re-opened
	// call by call, while distracted, which is the one posture in which
	// people say yes to things.
	if active := opts.active(); active != "" && profileName != active {
		return false, false
	}
	parked, err := consent.Ask(consent.Call{
		Cap:     c.ID,
		Safety:  string(c.Safety),
		Scopes:  grant.Scopes(c, values),
		Profile: profileName,
		Pin:     opts.connStamp(profileName, grant.Namespace(c.ID)),
		Agent:   opts.Agent,
		Args:    auditArgs(c, values),
		Why:     verr.Message,
		Preview: propose(ctx, c, opts, values, profileName),
	}, opts.ConsentWait)
	switch {
	case errors.Is(err, consent.ErrTooMany):
		// The queue is full, so this call gets the refusal it would have got
		// with no consent at all. Said out loud, because a flood of
		// questions is itself worth noticing: it is either an agent in a
		// retry loop or one waiting for the answer that comes when nobody is
		// reading any more.
		fmt.Fprintf(os.Stderr,
			"rta: %d requests are already waiting, so %s was refused without asking — "+
				"`rta agent pending` shows the queue\n", consent.MaxParked, c.ID)
		return false, false
	case errors.Is(err, consent.ErrTooBig):
		// A call whose arguments do not fit on a screen is not one anybody can
		// consent to by reading it, so it gets the refusal it would have got
		// with no consent at all rather than a prompt showing a fraction of
		// what is being approved.
		fmt.Fprintf(os.Stderr,
			"rta: %s was refused without asking — %v\n", c.ID, err)
		return false, false
	case err != nil:
		// A request that cannot be written is not a denial: fall back to
		// the refusal that would have happened without consent at all.
		fmt.Fprintln(os.Stderr, "rta: could not ask for consent:", err)
		return false, false
	}
	defer parked.Close()
	fmt.Fprintf(os.Stderr, "rta: %s is waiting for you — `rta agent allow %s` (or deny), %s\n",
		c.ID, parked.Request.ID, parked.Request.Deadline.Local().Format("15:04:05"))
	if opts.ConsentNotify {
		ringDoorbell(ctx, c.ID, parked.Request)
	}

	answer := parked.Wait(ctx)
	switch {
	case answer.Allowed:
		rec.Auth = agentlog.Live
		return true, true
	case answer.Answered:
		// These two answers are the ledger's own events, not any gate's, so
		// they carry their own codes: before the split they were the only
		// refusals with no stable name at all — one bare prose, one wearing
		// core.grant.required, the code of the question rather than of what
		// became of it.
		rec.Outcome, rec.Auth = agentlog.Refused, agentlog.Denied
		rec.Code, rec.Reason = "core.consent.declined", "the operator declined it"
		return false, true
	default:
		rec.Outcome, rec.Auth = agentlog.Refused, agentlog.Blocked
		rec.Code, rec.Reason = "core.consent.expired", "nobody answered before the request expired"
		return false, true
	}
}

// previewWait bounds the dry run. A preview that takes longer than this is
// a preview the operator is waiting on instead of reading, and the question
// is better asked without one.
const previewWait = 5 * time.Second

// propose runs a destructive call's own --dry-run so the operator approves
// an outcome rather than an intention.
//
// **Built-in capabilities only.** A dry run is an extra invocation of the
// handler, and on a request the operator goes on to *deny* it is an
// invocation that would otherwise never have happened — so previewing rests
// entirely on the handler telling the truth about DryRun. rta's own
// handlers are tested for that; a third-party plugin's promise is a claim,
// and the whole lesson of that is that a claim is not a fact. An external
// plugin's request is parked with the arguments and no preview, which is
// exactly what it got before this existed.
//
// Destructive only, for the same reason from the other side: a preview is
// worth an extra invocation where the answer is irreversible, and reads and
// writes are already described well enough by the capability and its
// arguments.
func propose(ctx context.Context, c plugin.Capability, opts Options,
	values map[string]any, profileName string) string {
	if !opts.ConsentPreview || c.Safety != plugin.Destructive || c.Run == nil {
		return ""
	}
	// A profiled call is not previewable here, and silence is the only safe
	// answer. The connection is resolved *after* consent — deliberately, so
	// that an unknown profile and an ungranted one produce the same refusal
	// — so a dry run at this point would run against whatever the capability
	// falls back to and describe the wrong place convincingly. A preview
	// that can be wrong is worse than none, because its whole job is to be
	// believed.
	if profileName != "" {
		return ""
	}
	if opts.Origin != nil {
		if o, ok := opts.Origin(grant.Namespace(c.ID)); ok && o.External() {
			return ""
		}
	}
	ctx, cancel := context.WithTimeout(ctx, previewWait)
	defer cancel()
	// Assembled the way the real call is assembled, minus the profile: same
	// surface, so a capability that refuses MCP refuses its preview too, and
	// the same resolution, so what is previewed is what would run.
	v, err := c.Run(ctx, plugin.NewRequest(plugin.Resolve(c, plugin.Inputs{
		Caller: values,
		Config: opts.pluginConfig(c),
	}), true, true).WithSurface(plugin.SurfaceMCP))
	if err != nil {
		// A preview that fails says nothing and blocks nothing: the operator
		// gets the request they would have got anyway.
		return ""
	}
	// Every dry run in the catalogue answers with one line of prose, and a
	// preview that needed rendering would be a second renderer to keep
	// honest. Anything else is treated as no preview at all.
	t, ok := v.(view.Text)
	if !ok {
		return ""
	}
	return textclean.Model(t.Body)
}

// bell latches off after one failure.
//
// A doorbell that failed once on this machine fails every time and for the
// same reason — nothing installed, no desktop session, a notification daemon
// that never answers — and each attempt costs the parked call up to
// notify's timeout. One penalty per server, then silence.
var bell struct {
	sync.Mutex
	off bool
}

// ringDoorbell tells the operator that something is waiting, and nothing
// else.
//
// **The doorbell says that somebody is asking, never what they said.** Every
// word of it is rta's own: the capability id, which pkg/plugin validated at
// registration, and the request id, which is hex this process generated.
// Nothing an agent chose — no record name, no argument, not even the profile
// it named, which at this point in the call has not been checked against the
// operator's config yet — reaches a channel that renders on a lock screen,
// gets read aloud by an accessibility tool, or persists in a notification
// centre. What the request actually asks for is one command away, in a
// terminal, where it is displayed by code that knows the text is untrusted.
func ringDoorbell(ctx context.Context, capID string, r consent.Request) {
	bell.Lock()
	defer bell.Unlock()
	if bell.off {
		return
	}
	err := notify.Send(ctx, notify.Note{
		Title: "rta — an agent is waiting",
		Body:  fmt.Sprintf("%s needs your answer · rta agent allow %s", capID, r.ID),
		TTL:   time.Until(r.Deadline),
	})
	if err != nil {
		bell.off = true
		fmt.Fprintln(os.Stderr, "rta: no desktop notification this time or after it:", err)
	}
}
