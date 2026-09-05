package grant

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/term"

	core "github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/guard"
	operatorid "github.com/this-is-tobi/rta/internal/operator"
	"github.com/this-is-tobi/rta/internal/stdio"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

func runGuardOn(_ context.Context, req plugin.Request) (view.View, error) {
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "the guard can only be enabled by a person")
	}
	if guard.Enabled() {
		return nil, view.Errorf("core.guard.exists", "the guard is already enabled").
			WithHint("`rta grant guard off` first, if you mean to rotate the passphrase")
	}
	held, verr := core.Load()
	if verr != nil {
		return nil, verr
	}
	if req.DryRun {
		return view.Text{Body: fmt.Sprintf("would enable the guard: issuing or renewing a grant "+
			"then requires the passphrase, and the %d grant(s) currently held are cleared — "+
			"they were issued without one", len(held))}, nil
	}
	pass, verr := guard.PromptSecret(req, true)
	if verr != nil {
		return nil, verr
	}
	// Clear first, enable second: a crash between the two leaves grants
	// cleared and the guard off, which is inconvenient and safe. The other
	// order leaves the guard on over unsigned rows, which loadAll would then
	// refuse as forgery — an alarm raised by the recovery, seal.go's own
	// phrase for the wrong shape.
	//
	// Cleared rather than migrated, and legacy() owns the argument: a
	// migration that re-signs what it finds is the same hole with more
	// steps, because the rows being blessed are exactly the rows whose
	// authorship the guard exists to pin. Grants are a day at most; what
	// this costs is re-issued in minutes, with the passphrase.
	// Both under the one grant lock: cleared and enabled used to be two
	// writes under two locks, and a `grant allow` in between passed the
	// guard check (still off), persisted an unsigned row, and the next
	// read refused the whole file as forged — a fail-closed alarm raised
	// by the recovery. Enabled inside the mutation, the window is gone;
	// a crash between the two writes leaves the guard on over an empty
	// file, which is the safe side.
	var enableErr *view.Error
	if verr := core.Mutate(func([]core.Grant) ([]core.Grant, bool) {
		if _, enableErr = guard.Enable(pass); enableErr != nil {
			return nil, false
		}
		return nil, true
	}); verr != nil {
		return nil, verr
	}
	if enableErr != nil {
		return nil, enableErr
	}
	return view.KeyValue{Pairs: []view.Pair{
		{Key: "guard", Value: "on — issuing or renewing a grant now asks for the passphrase"},
		{Key: "key", Value: guard.Fingerprint()},
		{Key: "cleared", Value: fmt.Sprintf("%d grant(s) issued before the guard", len(held))},
		{Key: "forgotten?", Value: "rm " + guard.Path() + " and the grants.json beside it starts clean"},
	}}, nil
}

func runGuardOff(_ context.Context, req plugin.Request) (view.View, error) {
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "the guard can only be disabled by a person")
	}
	if !guard.Enabled() {
		return nil, view.Errorf("core.guard.off", "the guard is not enabled")
	}
	held, verr := core.Load()
	if verr != nil {
		return nil, verr
	}
	// A remote guard has no passphrase to prove — its secrets live with
	// operators who are elsewhere — so the legitimate way off costs presence
	// at this terminal and nothing else. What still stands against an agent
	// with a shell here is what always stood: the running server's Pin, and
	// the audit trail of a guard that read "on" yesterday.
	if guard.Remote() {
		if req.DryRun {
			return view.Text{Body: fmt.Sprintf("would disable the remote guard, clearing the %d "+
				"grant(s) its operators signed", len(held))}, nil
		}
		// "Presence at this terminal" enforced, not assumed: without this, an
		// agent's shell tool tears the guard down more cleanly than the rm it
		// could always run — rm leaves orphaned signed grants screaming on
		// every read, guard off leaves the tidy was-never-enabled state.
		// rta must not be the attacker's quietest tool.
		if req.Surface() == plugin.SurfaceCLI && !term.IsTerminal(int(stdio.Real().Fd())) {
			return nil, view.Errorf("core.guard.remote.terminal",
				"disabling the remote guard needs a person at a terminal").
				WithHint("run this at a terminal, or from the TUI")
		}
		if verr := core.Mutate(func([]core.Grant) ([]core.Grant, bool) {
			return nil, true
		}); verr != nil {
			return nil, verr
		}
		if verr := guard.DisableRemote(); verr != nil {
			return nil, verr
		}
		return view.KeyValue{Pairs: []view.Pair{
			{Key: "guard", Value: "off — grants issue without an operator signature again"},
			{Key: "cleared", Value: fmt.Sprintf("%d grant(s) the operators had signed", len(held))},
		}}, nil
	}
	if req.DryRun {
		return view.Text{Body: fmt.Sprintf("would disable the guard after checking the passphrase, "+
			"clearing the %d grant(s) it signed", len(held))}, nil
	}
	pass, verr := guard.PromptSecret(req, false)
	if verr != nil {
		return nil, verr
	}
	// Proven before anything is touched: a wrong passphrase must cost
	// nothing, and especially not the grants.
	if _, verr := guard.Unlock(pass); verr != nil {
		return nil, verr
	}
	// Clear while the guard still stands, then remove it — the mirror of
	// enable's ordering, with the same crash story: dying between the two
	// leaves the guard on over an empty file, which a retry finishes.
	if verr := core.Mutate(func([]core.Grant) ([]core.Grant, bool) {
		return nil, true
	}); verr != nil {
		return nil, verr
	}
	if verr := guard.Disable(pass); verr != nil {
		return nil, verr
	}
	return view.KeyValue{Pairs: []view.Pair{
		{Key: "guard", Value: "off — grants issue without a passphrase again"},
		{Key: "cleared", Value: fmt.Sprintf("%d grant(s) the guard had signed", len(held))},
	}}, nil
}

// runGuardRemote is the provisioning-time enrollment: this machine's guard
// becomes the roster's public keys, and nothing else, ever. It shares
// guard-on's ordering — clear first, enable second — and its crash story.
func runGuardRemote(_ context.Context, req plugin.Request) (view.View, error) {
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "the guard can only be enabled by a person")
	}
	if guard.Enabled() {
		return nil, view.Errorf("core.guard.exists", "the guard is already enabled").
			WithHint("`rta grant guard off` first, if you mean to change what it trusts")
	}
	path := strings.TrimSpace(req.String("operators"))
	if path == "" {
		return nil, view.Errorf("core.guard.remote.roster", "name the roster file to enroll").
			WithHint("rta grant guard remote operators.txt --url https://rta.example.com")
	}
	rawURL := strings.TrimSpace(req.String("url"))
	if rawURL == "" {
		return nil, view.Errorf("core.guard.remote.server",
			"a remote guard needs this server's canonical URL (--url) — it is signed into every "+
				"grant, so a grant issued for this server verifies on no other").
			WithHint("the exact URL operators write in their remotes.yaml, and `rta mcp serve --operators-url` carries")
	}
	canonical, verr := operatorid.CanonicalServerURL("--url", rawURL)
	if verr != nil {
		return nil, verr
	}
	roster, groupReadable, err := operatorid.LoadRoster(path)
	if err != nil {
		return nil, view.Errorf("core.guard.remote.roster", "%v", err)
	}
	// Entries is already the signing subset: read-only rows never reach the
	// guard, and neither does a row whose expires= day has arrived (the
	// roster's own comments carry why). A roster of nothing but those can
	// watch a server, but a guard trusting nobody could never honour a
	// grant again — refused as the misconfiguration it is, not enabled as
	// a lockout.
	signers := roster.Entries()
	if len(signers) == 0 {
		return nil, view.Errorf("core.guard.remote.readonly",
			"every key in %s is role=read or already expired — a guard needs at least one "+
				"operator who can sign grants", path)
	}
	signerLabels := make([]string, 0, len(signers))
	for _, s := range signers {
		signerLabels = append(signerLabels, s.Label)
	}
	skipped := roster.Len() - len(signers)
	held, verr := core.Load()
	if verr != nil {
		return nil, verr
	}
	if req.DryRun {
		body := fmt.Sprintf("would enroll %s as this machine's guard, bound to %s — "+
			"grants are then honoured only when signed by one of them, issued over the operator "+
			"channel — and clear the %d grant(s) currently held",
			strings.Join(signerLabels, ", "), canonical, len(held))
		if skipped > 0 {
			body += fmt.Sprintf("; %d key(s) stay out of the guard (role=read, or already expired)", skipped)
		}
		return view.Text{Body: body}, nil
	}
	if verr := core.Mutate(func([]core.Grant) ([]core.Grant, bool) {
		return nil, true
	}); verr != nil {
		return nil, verr
	}
	if verr := guard.EnableRemote(signers, canonical); verr != nil {
		return nil, verr
	}
	operatorsCell := strings.Join(signerLabels, ", ")
	if skipped > 0 {
		operatorsCell += fmt.Sprintf(" — %d key(s) not enrolled (role=read, or already expired): "+
			"they cannot sign grants", skipped)
	}
	pairs := []view.Pair{
		{Key: "guard", Value: "remote — a grant is honoured only when an enrolled operator signed it"},
		{Key: "server", Value: canonical},
		{Key: "operators", Value: operatorsCell},
		{Key: "key", Value: guard.Fingerprint()},
		{Key: "cleared", Value: fmt.Sprintf("%d grant(s) issued before the guard", len(held))},
		{Key: "issuance", Value: "rta grant allow <capability> --server <this server>, from an enrolled machine"},
	}
	if groupReadable {
		// The serve path prints the same fact; the enrollment path is the
		// more trust-anchor-ish of the two, and must not be quieter.
		pairs = append(pairs, view.Pair{Key: "warning",
			Value: path + " is group-readable — anyone who can also write it can enroll themselves"})
	}
	return view.KeyValue{Pairs: pairs}, nil
}

func runGuardStatus(_ context.Context, req plugin.Request) (view.View, error) {
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "the guard's status is for the person at the terminal")
	}
	held, verr := core.Load()
	// The one state worth seeing first: the guard's own file is gone and
	// signed grants remain. Every issuing and listing path refuses it as
	// orphaned; this screen used to say "off" and offer to enable it.
	if verr != nil && verr.Code == "core.grant.guard.orphaned" {
		return view.KeyValue{Pairs: []view.Pair{
			{Key: "guard", Value: "ORPHANED — grants.json holds guard-signed grants and " + guard.Path() + " is gone; nothing is honoured"},
			{Key: "fix", Value: "rm " + core.Path() + ", then rta grant guard on"},
		}}, nil
	}
	if !guard.Enabled() {
		return view.KeyValue{Pairs: []view.Pair{
			{Key: "guard", Value: "off — any process running as you can issue a grant"},
			{Key: "enable", Value: "rta grant guard on"},
		}}, nil
	}
	if verr != nil {
		return nil, verr
	}
	if guard.Remote() {
		return view.KeyValue{Pairs: []view.Pair{
			{Key: "guard", Value: "remote — a grant is honoured only when an enrolled operator signed it"},
			{Key: "since", Value: guard.Created().Local().Format("2006-01-02 15:04")},
			{Key: "operators", Value: strings.Join(guard.OperatorLabels(), ", ")},
			{Key: "key", Value: guard.Fingerprint()},
			{Key: "grants", Value: fmt.Sprintf("%d held, all operator-signed", len(held))},
		}}, nil
	}
	return view.KeyValue{Pairs: []view.Pair{
		{Key: "guard", Value: "on — issuing or renewing a grant asks for the passphrase"},
		{Key: "since", Value: guard.Created().Local().Format("2006-01-02 15:04")},
		{Key: "key", Value: guard.Fingerprint()},
		{Key: "grants", Value: fmt.Sprintf("%d held, all guard-signed", len(held))},
	}}, nil
}
