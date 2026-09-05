package grant

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	core "github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

func renewCap(t *testing.T) plugin.Capability {
	t.Helper()
	for _, c := range Plugin(func() []plugin.Capability { return nil }).Capabilities {
		if c.ID == "grant.renew" {
			return c
		}
	}
	t.Fatal("grant.renew is not declared")
	return plugin.Capability{}
}

func renew(t *testing.T, values map[string]any) (view.View, error) {
	t.Helper()
	c := renewCap(t)
	return c.Run(context.Background(),
		plugin.NewRequest(plugin.Resolve(c, plugin.Inputs{Caller: values}), false, true).
			WithSurface(plugin.SurfaceCLI))
}

// Renewing a one-time grant leaves it one-time, and leaves what it has already
// spent spent.
//
// This is the defect renew exists for. "Renewing" was re-running `grant
// allow`, which builds a *fresh* grant from the flags of that invocation — so
// a person extending a `--max-uses 1` grant without retyping the flag silently
// converted it to unlimited and reset Uses to 0. The grant meant to reveal one
// secret once could then reveal it again, and again, and `grant list` showed a
// perfectly healthy row throughout.
func TestRenewExtendsTimeAndNothingElse(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	now := time.Now()
	if verr := core.Save([]core.Grant{{
		Target: "kv.get", Scope: "db-password", Profile: "staging",
		Issued: now.Add(-10 * time.Minute), Expires: now.Add(5 * time.Minute),
		TTL: "15m", MaxUses: 3, Uses: 2, Note: "incident 4412",
	}}); verr != nil {
		t.Fatal(verr)
	}

	if _, err := renew(t, nil); err != nil {
		t.Fatal(err)
	}

	got, verr := core.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	if len(got) != 1 {
		t.Fatalf("expected one grant, got %d", len(got))
	}
	g := got[0]
	if !g.Expires.After(now.Add(5 * time.Minute)) {
		t.Errorf("expires = %v, want it pushed out", g.Expires)
	}
	if g.MaxUses != 3 {
		t.Errorf("maxUses = %d, want 3 — a renewal must not lift the cap", g.MaxUses)
	}
	if g.Uses != 2 {
		t.Errorf("uses = %d, want 2 — a renewal must not give back what was spent", g.Uses)
	}
	for _, check := range []struct{ name, got, want string }{
		{"scope", g.Scope, "db-password"},
		{"profile", g.Profile, "staging"},
		{"note", g.Note, "incident 4412"},
	} {
		if check.got != check.want {
			t.Errorf("%s = %q, want %q carried forward", check.name, check.got, check.want)
		}
	}
}

// The moment of first consent does not move, so a chain of renewals is capped
// absolutely.
//
// Active() already tests now.Before(Issued.Add(MaxTTL)) on every read, so
// leaving Issued alone is what makes the 24h ceiling survive any number of
// renewals for no extra code. Moving it would let consent be made perpetual a
// quarter hour at a time, which is the one thing a time-boxed permission must
// not permit.
func TestRenewingRepeatedlyCannotOutliveTheCeiling(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	firstConsent := time.Now().Add(-23 * time.Hour)
	if verr := core.Save([]core.Grant{{
		Target: "pg", Profile: "staging",
		Issued: firstConsent, Expires: time.Now().Add(time.Minute), TTL: "15m",
	}}); verr != nil {
		t.Fatal(verr)
	}

	v, err := renew(t, map[string]any{"ttl": "8h"})
	if err != nil {
		t.Fatal(err)
	}
	body := v.(view.Text).Body
	if !strings.Contains(body, "capped") {
		t.Errorf("a renewal clamped by the ceiling did not say so:\n%s", body)
	}

	got, verr := core.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	if len(got) != 1 {
		t.Fatalf("expected one grant, got %d", len(got))
	}
	if !got[0].Issued.Equal(firstConsent) {
		t.Errorf("issued moved to %v; a chain of renewals can now outlive the %v ceiling",
			got[0].Issued, core.MaxTTL)
	}
	if ceiling := firstConsent.Add(core.MaxTTL); got[0].Expires.After(ceiling) {
		t.Errorf("expires = %v, past the ceiling %v", got[0].Expires, ceiling)
	}
}

// Renew only touches grants that are still standing. A spent or expired one is
// a fresh decision, which is `grant allow`.
func TestRenewLeavesASpentGrantSpent(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	now := time.Now()
	if verr := core.Save([]core.Grant{{
		Target: "kv.get", Issued: now, Expires: now.Add(time.Hour), MaxUses: 1, Uses: 1,
	}}); verr != nil {
		t.Fatal(verr)
	}
	v, err := renew(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if body := v.(view.Text).Body; !strings.Contains(body, "Nothing to renew") {
		t.Errorf("a fully spent grant was renewed:\n%s", body)
	}
}

// Renewing one connection does not touch another.
func TestRenewNarrowsToTheProfileNamed(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	now := time.Now()
	soon := now.Add(time.Minute)
	if verr := core.Save([]core.Grant{
		{Target: "pg", Profile: "staging", Issued: now, Expires: soon, TTL: "1h"},
		{Target: "pg", Profile: "prod", Issued: now, Expires: soon, TTL: "1h"},
	}); verr != nil {
		t.Fatal(verr)
	}
	if _, err := renew(t, map[string]any{"profile": "staging"}); err != nil {
		t.Fatal(err)
	}
	got, verr := core.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	for _, g := range got {
		switch g.Profile {
		case "staging":
			if !g.Expires.After(soon) {
				t.Error("the named connection was not renewed")
			}
		case "prod":
			if g.Expires.After(soon) {
				t.Error("renewing staging also renewed prod")
			}
		}
	}
}

// A grant is one per target+scope+profile, so allowing a second connection
// does not revoke the first.
//
// Without profile in the dedupe key this was destructive: `grant allow pg
// --profile b` deleted the grant for profile a while reporting only that b had
// been allowed — a silent revocation nobody asked for, visible only by reading
// `grant list` afterwards.
func TestAllowingASecondConnectionKeepsTheFirst(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	cfg := t.TempDir() + "/config.yaml"
	if err := writeConfig(cfg, `
profiles:
  staging:
    plugins:
      kv:
        set:
          identity: x
  prod:
    plugins:
      kv:
        set:
          identity: y
`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RTA_CONFIG", cfg)

	catalog := func() []plugin.Capability {
		return []plugin.Capability{{ID: "kv.get", Summary: "get", Safety: plugin.Read}}
	}
	allow := func(profile string) {
		t.Helper()
		var c plugin.Capability
		for _, cap := range Plugin(catalog).Capabilities {
			if cap.ID == "grant.allow" {
				c = cap
			}
		}
		if _, err := c.Run(context.Background(), plugin.NewRequest(
			plugin.Resolve(c, plugin.Inputs{Caller: map[string]any{
				"target": "kv", "profile": profile, "ttl": "15m",
			}}), false, true).WithSurface(plugin.SurfaceCLI)); err != nil {
			t.Fatalf("allow %s: %v", profile, err)
		}
	}
	allow("staging")
	allow("prod")

	got, verr := core.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g.Profile] = true
	}
	if !seen["staging"] {
		t.Error("allowing prod deleted the grant for staging")
	}
	if !seen["prod"] {
		t.Error("the grant for prod was not stored")
	}
}

func writeConfig(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// The same selector as revoke: a plugin name takes every grant inside it.
// `renew kv` used to match nothing while `revoke kv` took them all.
func TestRenewOfAPluginTakesEveryGrantInsideIt(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	now := time.Now()
	if verr := core.Save([]core.Grant{
		{Target: "kv.get", Scope: "a", Issued: now.Add(-time.Minute), Expires: now.Add(time.Minute), TTL: "2m"},
		{Target: "kv.rm", Scope: "b", Issued: now.Add(-time.Minute), Expires: now.Add(time.Minute), TTL: "2m"},
		{Target: "note.rm", Scope: "c", Issued: now.Add(-time.Minute), Expires: now.Add(time.Minute), TTL: "2m"},
	}); verr != nil {
		t.Fatal(verr)
	}
	if _, err := renew(t, map[string]any{"target": "kv", "ttl": "30m"}); err != nil {
		t.Fatal(err)
	}
	got, verr := core.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	for _, g := range got {
		extended := g.Expires.After(now.Add(10 * time.Minute))
		if strings.HasPrefix(g.Target, "kv.") && !extended {
			t.Errorf("%s was not renewed by `renew kv`", g.Target)
		}
		if g.Target == "note.rm" && extended {
			t.Errorf("note.rm was renewed by `renew kv`")
		}
	}
}

// Renew caps where the gate caps. A team ceiling bounds a grant from first
// consent and Load drops it there; renew used to print a deadline past it
// and never say the ceiling bit.
func TestRenewIsCappedByTheTeamCeilingAndSaysSo(t *testing.T) {
	setup(t)
	withPolicy(t, "maxTTL: 20m\n")
	now := time.Now()
	if verr := core.Save([]core.Grant{{
		Target: "kv.get", Scope: "db", Issued: now.Add(-10 * time.Minute), Expires: now.Add(5 * time.Minute), TTL: "15m",
	}}); verr != nil {
		t.Fatal(verr)
	}
	v, err := renew(t, map[string]any{"ttl": "1h"})
	if err != nil {
		t.Fatal(err)
	}
	got, verr := core.Load()
	if verr != nil || len(got) != 1 {
		t.Fatalf("load = %v %v", got, verr)
	}
	if limit := now.Add(10 * time.Minute); got[0].Expires.After(limit.Add(2 * time.Second)) {
		t.Errorf("expires = %v, want at most the team ceiling from first consent (%v)", got[0].Expires, limit)
	}
	if body := fmt.Sprint(v); !strings.Contains(body, "capped") && !strings.Contains(body, "ceiling") {
		t.Errorf("renew did not say the ceiling bit: %s", body)
	}
}
