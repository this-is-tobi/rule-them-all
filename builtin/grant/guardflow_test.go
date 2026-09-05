package grant

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	core "github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/guard"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// reqTUI is req through the TUI's masked form — the surface that may carry
// the passphrase as a value, since the CLI refuses it on argv.
func reqTUI(values map[string]any) plugin.Request {
	return plugin.NewRequest(values, false, true).WithSurface(plugin.SurfaceTUI)
}

// guardCap fetches one of the plugin's declared capabilities, so the flow
// under test is the declared one — field list included — and not a bare
// handler the declaration could drift from.
func guardCap(t *testing.T, id string) plugin.Capability {
	t.Helper()
	for _, c := range Plugin(catalog).Capabilities {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no capability %q", id)
	return plugin.Capability{}
}

func guardOn(t *testing.T, pass string) {
	t.Helper()
	old := guard.ScryptWorkFactor
	guard.ScryptWorkFactor = 10
	t.Cleanup(func() { guard.ScryptWorkFactor = old })
	if _, err := guardCap(t, "grant.guard.on").Run(context.Background(),
		reqTUI(map[string]any{"passphrase": pass})); err != nil {
		t.Fatal(err)
	}
}

func code(t *testing.T, err error) string {
	t.Helper()
	verr, ok := err.(*view.Error)
	if !ok {
		t.Fatalf("want a view.Error, got %T: %v", err, err)
	}
	return verr.Code
}

// **The whole feature in one test.** With the guard on, `grant allow` without
// the passphrase is refused — in this harness there is no terminal to prompt
// at, which is exactly what an agent's shell looks like — and with it, the
// grant issues signed and loads.
func TestGuardOnGatesGrantAllow(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	allow := guardCap(t, "grant.allow")

	_, err := allow.Run(context.Background(),
		req(map[string]any{"target": "kv.get", "ttl": "15m"}))
	if err == nil {
		t.Fatal("the guard let an allow through with no passphrase")
	}
	if got := code(t, err); got != "core.guard.passphrase.required" {
		t.Fatalf("code = %s, want core.guard.passphrase.required", got)
	}
	if grants, _ := core.Load(); len(grants) != 0 {
		t.Fatalf("%d grants stored after a refusal", len(grants))
	}

	if _, err := allow.Run(context.Background(),
		reqTUI(map[string]any{"target": "kv.get", "ttl": "15m", "passphrase": "correct horse"})); err != nil {
		t.Fatal(err)
	}
	grants, verr := core.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	if len(grants) != 1 || grants[0].Sig == "" {
		t.Fatalf("loaded %+v, want one signed grant", grants)
	}
}

// A wrong passphrase is refused by the unlock, not by a failed signature
// three layers down — the operator is told the actual problem.
func TestAWrongPassphraseIsNamedAsSuch(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	_, err := guardCap(t, "grant.allow").Run(context.Background(),
		reqTUI(map[string]any{"target": "kv.get", "ttl": "15m", "passphrase": "wrong horse"}))
	if err == nil {
		t.Fatal("a wrong passphrase issued a grant")
	}
	if got := code(t, err); got != "core.guard.passphrase" {
		t.Fatalf("code = %s, want core.guard.passphrase", got)
	}
}

// A dry run mints nothing, so it must not demand the secret — it is how the
// TUI previews the grant before anyone commits — and it says the guard will
// ask, so the prompt that follows is never a surprise.
func TestADryRunNeedsNoPassphraseAndSaysTheGuardWill(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	c := guardCap(t, "grant.allow")
	v, err := c.Run(context.Background(), plugin.NewRequest(
		map[string]any{"target": "kv.get", "ttl": "15m"}, true, true).WithSurface(plugin.SurfaceCLI))
	if err != nil {
		t.Fatal(err)
	}
	body := v.(view.Text).Body
	if !strings.Contains(body, "passphrase") {
		t.Fatalf("the preview does not warn about the prompt: %q", body)
	}
}

// Renewing extends authority, so it costs the passphrase exactly as issuing
// does — and the extended grant re-verifies, or loadAll would refuse the
// whole file as forged on the read after the renewal.
func TestRenewUnderTheGuardCostsThePassphraseAndResigns(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	allow, renew := guardCap(t, "grant.allow"), guardCap(t, "grant.renew")
	if _, err := allow.Run(context.Background(),
		reqTUI(map[string]any{"target": "kv.get", "ttl": "15m", "passphrase": "correct horse"})); err != nil {
		t.Fatal(err)
	}
	before, _ := core.Load()

	if _, err := renew.Run(context.Background(), req(map[string]any{"ttl": "1h"})); err == nil {
		t.Fatal("a renewal extended authority with no passphrase")
	}
	if _, err := renew.Run(context.Background(),
		reqTUI(map[string]any{"ttl": "1h", "passphrase": "correct horse"})); err != nil {
		t.Fatal(err)
	}
	after, verr := core.Load()
	if verr != nil {
		t.Fatalf("the renewed file does not verify: %v", verr)
	}
	if len(after) != 1 || !after[0].Expires.After(before[0].Expires) {
		t.Fatalf("renewal did not extend: before %v, after %+v", before[0].Expires, after)
	}
}

// Revoking stays passphrase-free: taking authority away is the fail-safe
// direction, and an incident is the wrong moment to demand a secret.
func TestRevokeNeedsNoPassphrase(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	if _, err := guardCap(t, "grant.allow").Run(context.Background(),
		reqTUI(map[string]any{"target": "kv.get", "ttl": "15m", "passphrase": "correct horse"})); err != nil {
		t.Fatal(err)
	}
	if _, err := guardCap(t, "grant.revoke").Run(context.Background(),
		req(map[string]any{"all": true})); err != nil {
		t.Fatal(err)
	}
	if grants, _ := core.Load(); len(grants) != 0 {
		t.Fatalf("%d grants survived a revoke", len(grants))
	}
}

// The way off costs what turning it on promised; a wrong passphrase costs
// nothing, especially not the grants.
func TestGuardOffProvesThePassphraseAndClears(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	if _, err := guardCap(t, "grant.allow").Run(context.Background(),
		reqTUI(map[string]any{"target": "kv.get", "ttl": "15m", "passphrase": "correct horse"})); err != nil {
		t.Fatal(err)
	}
	off := guardCap(t, "grant.guard.off")

	if _, err := off.Run(context.Background(),
		reqTUI(map[string]any{"passphrase": "wrong horse"})); err == nil {
		t.Fatal("the guard came off without its passphrase")
	}
	if grants, _ := core.Load(); len(grants) != 1 {
		t.Fatal("a refused disable touched the grants")
	}

	if _, err := off.Run(context.Background(),
		reqTUI(map[string]any{"passphrase": "correct horse"})); err != nil {
		t.Fatal(err)
	}
	if guard.Enabled() {
		t.Fatal("still enabled after a proven disable")
	}
	if grants, verr := core.Load(); verr != nil || len(grants) != 0 {
		t.Fatalf("after disable: %d grants, err %v", len(grants), verr)
	}
}

// Enabling clears what was issued without a passphrase — blessing it
// wholesale would launder exactly what the guard exists to pin.
func TestEnablingClearsPreGuardGrants(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	if _, err := guardCap(t, "grant.allow").Run(context.Background(),
		req(map[string]any{"target": "kv.get", "ttl": "15m"})); err != nil {
		t.Fatal(err)
	}
	guardOn(t, "correct horse")
	if grants, verr := core.Load(); verr != nil || len(grants) != 0 {
		t.Fatalf("after enable: %d grants, err %v", len(grants), verr)
	}
}

// The flag is the one channel that leaks — argv is readable by every process
// and lands in shell history — so the CLI refuses it outright rather than
// warning about it. The TUI's masked field, exercised by every other test
// here, is the surface that may carry the value.
func TestThePassphraseFlagIsRefusedOnTheCLI(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	_, err := guardCap(t, "grant.allow").Run(context.Background(),
		req(map[string]any{"target": "kv.get", "ttl": "15m", "passphrase": "correct horse"}))
	if err == nil {
		t.Fatal("a passphrase on argv was accepted")
	}
	if got := code(t, err); got != "core.guard.passphrase.argv" {
		t.Fatalf("code = %s, want core.guard.passphrase.argv", got)
	}
	if grants, _ := core.Load(); len(grants) != 0 {
		t.Fatal("the refused flag still issued a grant")
	}
}

// `guard status` used to say "off" and offer to enable it when the guard's
// own file was gone and signed grants remained — the one state every
// issuing and listing path already refuses as orphaned.
func TestGuardStatusSaysOrphanedWhenTheGuardFileIsGone(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	guardOn(t, "correct horse")
	if _, err := guardCap(t, "grant.allow").Run(context.Background(),
		reqTUI(map[string]any{"target": "kv.get", "ttl": "15m", "passphrase": "correct horse"})); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(guard.Path()); err != nil {
		t.Fatal(err)
	}
	v, err := guardCap(t, "grant.guard.status").Run(context.Background(), req(nil))
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprint(v)
	if !strings.Contains(body, "ORPHANED") || strings.Contains(body, "off —") {
		t.Fatalf("guard status hides the orphaned state: %s", body)
	}
}

// A target the team forbids is refused before the passphrase is asked for,
// not after it was typed.
func TestTheCeilingIsCheckedBeforeThePassphrase(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	withPolicy(t, "never: [kv.get]\n")
	guardOn(t, "correct horse")
	// No passphrase supplied: with the ceiling checked first, the refusal
	// is the policy's; it used to be the missing passphrase.
	_, err := guardCap(t, "grant.allow").Run(context.Background(),
		req(map[string]any{"target": "kv.get", "ttl": "15m"}))
	if err == nil {
		t.Fatal("a forbidden target was allowed")
	}
	if c := code(t, err); c == "core.guard.passphrase.required" {
		t.Fatalf("the passphrase was asked for before the policy said no: %s", c)
	}
}
