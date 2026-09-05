package tui

import (
	"context"
	"testing"

	"github.com/this-is-tobi/rta/internal/config"
	"github.com/this-is-tobi/rta/internal/registry"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// Carrying on from the result on screen.
//
// One property: a form that continues from a result opens showing what that
// result was produced with. `e` means edit, not type it all again — and a row
// action acts on the listing it was pressed in, not on that capability's
// declared defaults.

// storePlugin is a listing and a removal over the same store, the shape every
// row action in the app has: `list` names where to look, `rm` acts on one row
// and needs to be told the same where.
func storePlugin() plugin.Plugin {
	run := func(context.Context, plugin.Request) (view.View, error) {
		return view.Table{
			Columns: []view.Column{{Name: "Name"}},
			Rows:    [][]string{{"one"}, {"two"}},
		}, nil
	}
	where := plugin.Field{Name: "bucket", Type: plugin.String,
		Help: "which store to work in — empty means the default one"}
	return plugin.Plugin{
		Name: "store", Summary: "a store with a listing and a removal",
		Capabilities: []plugin.Capability{
			{ID: "store.list", Summary: "list", Safety: plugin.Read,
				Inputs: []plugin.Field{where,
					{Name: "prefix", Type: plugin.String, Help: "only names under this"}},
				Run: run},
			{ID: "store.rm", Summary: "remove", Safety: plugin.Destructive,
				Inputs: []plugin.Field{
					{Name: "name", Type: plugin.String, Positional: true, Required: true, Help: "what to remove"},
					where},
				Run: run},
		},
	}
}

func storeModel(t *testing.T) Model {
	t.Helper()
	t.Setenv("RTA_CONFIG", t.TempDir()+"/config.yaml")
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	reg := registry.New()
	if err := reg.Register(storePlugin()); err != nil {
		t.Fatal(err)
	}
	m := New(reg, config.Dashboard{}, nil)
	m.width, m.height = 100, 40
	return m
}

// `e` on a result opens the boxes on what that result was produced with.
//
// Reported plainly: editing the inputs of an `s3 object list` lost the bucket,
// so the operator retyped it every time. "Edit inputs" that opens on the
// declared defaults is not editing.
func TestEditingAResultKeepsWhatItWasRunWith(t *testing.T) {
	m := storeModel(t)
	list, _ := m.reg.Capability("store.list")
	m.current = list
	m.lastValues = map[string]any{"bucket": "mine", "prefix": "photos/", "detail": true}

	model, _ := m.startForm(list, m.lastValues)
	next := model.(Model)
	if next.form == nil {
		t.Fatal("no form opened")
	}
	if got := *next.form.bindings["bucket"]; got != "mine" {
		t.Errorf("bucket box = %q, want the one this result came from", got)
	}
	if got := *next.form.bindings["prefix"]; got != "photos/" {
		t.Errorf("prefix box = %q, want the one this result came from", got)
	}
	// And the half no field can ask about still travels beside them.
	if got := next.form.values()["detail"]; got != true {
		t.Errorf("detail = %v, want the toggle carried through the form", got)
	}
}

// A row action carries the listing's own inputs into the form it opens.
//
// This is the sharper half, because it is silent and destructive. `net hosts
// list --file ./container/hosts` then `x` on a row opened a removal form whose
// `file` box was empty — and empty means the system hosts file. The screen said
// container, the action would have edited the machine.
func TestARowActionActsOnTheListingItWasPressedIn(t *testing.T) {
	m := storeModel(t)
	list, _ := m.reg.Capability("store.list")
	rm, _ := m.reg.Capability("store.rm")
	m.current = list
	m.lastValues = map[string]any{"bucket": "mine", "prefix": "photos/"}
	m.row = 1

	tbl := view.Table{Columns: []view.Column{{Name: "Name"}}, Rows: [][]string{{"one"}, {"two"}}}
	model, _ := m.runAction(capAction{key: "x", label: "remove", cap: rm, src: srcRow}, tbl)
	next := model.(Model)
	if next.form == nil {
		t.Fatal("a destructive row action did not open a form")
	}
	if got := *next.form.bindings["bucket"]; got != "mine" {
		t.Errorf("bucket box = %q — the removal would have gone somewhere else than the listing", got)
	}
	// The row's own identity still wins, and is not asked about again.
	if got := next.form.values()["name"]; got != "two" {
		t.Errorf("name = %v, want the row under the cursor", got)
	}
	// An input the removal does not declare is not smuggled in.
	if _, carried := next.form.values()["prefix"]; carried {
		t.Error("an input store.rm does not declare was carried into its request")
	}
}

// Nothing is carried between plugins. An input of the same name in another
// namespace is a different thing, and guessing would pre-fill a destructive
// form with somebody else's value.
func TestNothingIsCarriedAcrossPlugins(t *testing.T) {
	m := storeModel(t)
	rm, _ := m.reg.Capability("store.rm")
	m.current = plugin.Capability{ID: "other.list", Summary: "elsewhere"}
	m.lastValues = map[string]any{"bucket": "somebody-elses"}

	if got := m.continuing(rm); len(got) != 0 {
		t.Errorf("carried %v across a namespace boundary", got)
	}
}

// A value somebody typed survives a re-edit even when it matches what the
// environment would have supplied.
//
// The drop rule exists so an untouched box does not pin the call to an
// environment the picker has moved away from. It must not reach a value the
// person gave: on the second run that would take a deliberate --host away and
// quietly send the call back to the profile's.
func TestATypedValueSurvivesAReEditEvenWhenItMatchesTheEnvironment(t *testing.T) {
	m := profileModel(t, twoProfileConfig())
	switchOn(t, &m, "staging")
	c := dbPlugin().Capabilities[0]

	// The operator typed staging's own host explicitly last run.
	prev := map[string]any{"host": "staging.internal"}
	model, _ := m.startForm(c, prev)
	next := model.(Model)
	if got := *next.form.bindings["host"]; got != "staging.internal" {
		t.Fatalf("host box = %q", got)
	}
	if next.form.derived["host"] {
		t.Error("a value the caller already had is marked as a display")
	}
	if got := next.form.values()["host"]; got != "staging.internal" {
		t.Errorf("host = %v — a value somebody typed was dropped as a display", got)
	}
}

// And the environment's own contribution is still treated as a display.
func TestTheEnvironmentsOwnContributionIsStillADisplay(t *testing.T) {
	m := profileModel(t, twoProfileConfig())
	switchOn(t, &m, "staging")
	c := dbPlugin().Capabilities[0]

	model, _ := m.startForm(c, nil)
	next := model.(Model)
	if !next.form.derived["host"] {
		t.Fatal("the environment's value is not marked as a display")
	}
	if _, answered := next.form.values()["host"]; answered {
		t.Error("an untouched environment value came back as an answer")
	}
}

// A row seeds every input it shows a column for, not only the identity: a
// grant row carries its record, agent and profile, and `x` on one of two
// note.rm rows used to revoke both because only the target seeded.
func TestARowSeedsEveryInputItShowsAColumnFor(t *testing.T) {
	m := storeModel(t)
	revoke := plugin.Capability{
		ID: "demo.revoke", Summary: "revoke", Safety: plugin.Destructive,
		Inputs: []plugin.Field{
			{Name: "target", Type: plugin.String, Positional: true},
			{Name: "scope", Type: plugin.String, Positional: true},
			{Name: "agent", Type: plugin.String},
			{Name: "profile", Type: plugin.String},
			{Name: "all", Type: plugin.Bool},
		},
		Run: func(context.Context, plugin.Request) (view.View, error) { return view.Text{}, nil },
	}
	m.row = 1
	tbl := view.Table{
		Columns: []view.Column{{Name: "Target"}, {Name: "Agent"}, {Name: "Record"}, {Name: "Profile"}},
		Rows:    [][]string{{"note.rm", "claude", "1", "—"}, {"note.rm", "cursor", "2", "—"}},
	}
	model, _ := m.runAction(capAction{key: "x", label: "revoke", cap: revoke, src: srcRow}, tbl)
	next := model.(Model)
	if next.form == nil {
		t.Fatal("a destructive row action did not open a form")
	}
	got := next.form.values()
	if got["target"] != "note.rm" || got["scope"] != "2" || got["agent"] != "cursor" {
		t.Errorf("seeded %v, want the row's target, record (as scope) and agent", got)
	}
	if v, ok := got["profile"]; ok && v != "" {
		t.Errorf("an em dash seeded profile = %v", v)
	}
}
