package wire

import (
	"context"
	"reflect"
	"testing"

	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
	rtav1 "github.com/this-is-tobi/rta/proto/rta/v1"
	"google.golang.org/protobuf/proto"
)

// The generated *_name maps hold every value declared in the .proto, so they
// are an oracle rather than a restatement: a value added to the contract and
// not to a mapping table here fails, and nothing has to be remembered.
//
// UNSPECIFIED is excluded because it is not a member of the set — it is what
// the wire says when the sender did not say, and it deliberately has no Go
// counterpart to decode to.

func TestEverySafetyOnTheWireHasAMapping(t *testing.T) {
	for v, name := range rtav1.Safety_name {
		if rtav1.Safety(v) == rtav1.Safety_SAFETY_UNSPECIFIED {
			continue
		}
		got, ok := SafetyFromProto(rtav1.Safety(v))
		if !ok {
			t.Errorf("%s is in the contract and decodes to nothing", name)
			continue
		}
		if back := SafetyToProto(got); back != rtav1.Safety(v) {
			t.Errorf("%s round-tripped to %s", name, back)
		}
	}
	// And the other direction: a class Go has that the wire cannot carry
	// would encode as UNSPECIFIED, which the far side refuses — a capability
	// that silently stops being destructive is the worst available failure.
	for _, s := range plugin.Safeties() {
		if SafetyToProto(s) == rtav1.Safety_SAFETY_UNSPECIFIED {
			t.Errorf("plugin.Safety %q has no wire form, so it would cross as unspecified", s)
		}
	}
}

func TestEveryFieldTypeOnTheWireHasAMapping(t *testing.T) {
	for v, name := range rtav1.FieldType_name {
		if rtav1.FieldType(v) == rtav1.FieldType_FIELD_TYPE_UNSPECIFIED {
			continue
		}
		got, ok := FieldTypeFromProto(rtav1.FieldType(v))
		if !ok {
			t.Errorf("%s is in the contract and decodes to nothing", name)
			continue
		}
		if back := FieldTypeToProto(got); back != rtav1.FieldType(v) {
			t.Errorf("%s round-tripped to %s", name, back)
		}
	}
	// plugin.FieldTypes() is the closed set. A type declared in Go
	// with no wire form would cross as unspecified, and the receiving host
	// would report it as unknown — safe, but at run time on somebody else's
	// machine rather than here.
	for _, ft := range plugin.FieldTypes() {
		if FieldTypeToProto(ft) == rtav1.FieldType_FIELD_TYPE_UNSPECIFIED {
			t.Errorf("plugin.FieldType %q has no wire form; add it to proto/rta/v1 and to fieldTypes", ft)
		}
	}
}

// The same coverage in both directions for endpoint roles, and the second
// half matters more than it does for FieldType.
//
// A role declared in Go with no wire form crosses as unspecified, and the
// receiving host reads that as "not filled from a tunnel". Nothing reports it:
// the plugin loads, the capability runs, and the call reaches the plugin's own
// default host instead of the cluster the operator pointed it at. That is a
// silently wrong destination rather than a refusal, which is the failure mode
// this whole feature is built to remove.
func TestEveryEndpointRoleOnTheWireHasAMapping(t *testing.T) {
	for v, name := range rtav1.EndpointRole_name {
		if rtav1.EndpointRole(v) == rtav1.EndpointRole_ENDPOINT_ROLE_UNSPECIFIED {
			continue
		}
		got := EndpointRoleFromProto(rtav1.EndpointRole(v))
		if got == plugin.EndpointNone {
			t.Errorf("%s is in the contract and decodes to no role", name)
			continue
		}
		if back := EndpointRoleToProto(got); back != rtav1.EndpointRole(v) {
			t.Errorf("%s round-tripped to %s", name, back)
		}
	}
	for _, role := range plugin.EndpointRoles() {
		if role == plugin.EndpointNone {
			continue
		}
		if EndpointRoleToProto(role) == rtav1.EndpointRole_ENDPOINT_ROLE_UNSPECIFIED {
			t.Errorf("plugin.EndpointRole %q has no wire form, so an input declaring it "+
				"crosses as \"no tunnel\" and the call silently reaches the plugin's default host", role)
		}
	}
}

func TestEverySurfaceOnTheWireHasAMapping(t *testing.T) {
	for v, name := range rtav1.Surface_name {
		if rtav1.Surface(v) == rtav1.Surface_SURFACE_UNSPECIFIED {
			continue
		}
		got := SurfaceFromProto(rtav1.Surface(v))
		if got == plugin.SurfaceUnknown {
			t.Errorf("%s is in the contract and decodes to unknown", name)
			continue
		}
		if back := SurfaceToProto(got); back != rtav1.Surface(v) {
			t.Errorf("%s round-tripped to %s", name, back)
		}
	}
}

func TestEveryChartAndColumnKindOnTheWireHasAMapping(t *testing.T) {
	for v, name := range rtav1.ChartKind_name {
		if rtav1.ChartKind(v) == rtav1.ChartKind_CHART_KIND_UNSPECIFIED {
			continue
		}
		got := chartKindFromProto(rtav1.ChartKind(v))
		if got == "" {
			t.Errorf("%s is in the contract and decodes to nothing", name)
			continue
		}
		if back := chartKindToProto(got); back != rtav1.ChartKind(v) {
			t.Errorf("%s round-tripped to %s", name, back)
		}
	}
	// ColumnKind's zero value is meaningful — it is plain text, matching Go's
	// empty string — so nothing is excluded here.
	for v, name := range rtav1.ColumnKind_name {
		got := columnKindFromProto(rtav1.ColumnKind(v))
		if back := columnKindToProto(got); back != rtav1.ColumnKind(v) {
			t.Errorf("%s round-tripped to %s", name, back)
		}
	}
}

// everyViewType is one instance of each member of the union, with every field
// set to something distinguishable from its zero value.
//
// Zero values are what makes a round-trip test lie: a field the encoder never
// writes round-trips perfectly when it is empty on both sides. So Total is not
// 0, Markdown is not false, Redacted is not nil, and the nesting is deep
// enough that a recursive encoder that stops at depth one fails.
func everyViewType() map[string]view.View {
	return map[string]view.View{
		"text": view.Text{Body: "body", Markdown: true},
		"keyvalue": view.KeyValue{
			Pairs:    []view.Pair{{Key: "k", Value: "v"}, {Key: "secret", Value: "s"}},
			Redacted: []string{"secret"},
		},
		"table": view.Table{
			Columns:  []view.Column{{Name: "A", Kind: view.KindBytes}, {Name: "B", Kind: view.KindStatus}},
			Rows:     [][]string{{"1", "ok"}, {"2", "bad"}},
			Total:    99,
			Page:     &view.Cursor{Next: "cursor-token"},
			Redacted: []string{"B"},
			Tail:     true,
		},
		"tree": view.Tree{Roots: []view.Node{
			{Label: "root", Detail: "d", Children: []view.Node{
				{Label: "child", Detail: "cd", Children: []view.Node{{Label: "grandchild", Detail: "gd"}}},
			}},
			{Label: "second root"},
		}},
		"chart": view.Chart{
			Kind:   view.ChartLine,
			Series: []view.Series{{Name: "cpu", Points: []float64{1, 2.5, 3}}},
			Unit:   "%",
			Max:    100,
		},
		"sections": view.Sections{
			Items: []view.Section{
				{ID: "one", Title: "One", View: view.Text{Body: "inner", Markdown: true}},
				// A nested composite: a section holding a page holding a view.
				{ID: "two", Title: "Two", View: view.Sections{
					Items: []view.Section{{Title: "Nested", View: view.KeyValue{
						Pairs: []view.Pair{{Key: "deep", Value: "yes"}},
					}}},
				}},
				// A section with a heading and nothing under it, which is
				// legal and is how a page reports an empty part.
				{Title: "Empty"},
			},
			Warnings: []view.Error{{Code: "x.partial", Message: "one sensor failed", Hint: "try later", Retryable: true}},
		},
		// Refusal set so the round-trip proves the flag survives the wire: a
		// plugin's policy gate that arrives stripped would ledger host-side
		// as the work breaking.
		"error": &view.Error{Code: "x.y.z", Message: "it failed", Hint: "do this", Retryable: true, Refusal: true},
	}
}

// A view that does not survive the wire is a plugin whose output is silently
// different from a built-in's — a second-class plugin, in the least visible way
// available: the capability works, the numbers are right, and one column has
// lost the hint that made it align.
func TestEveryViewSurvivesARoundTrip(t *testing.T) {
	for name, v := range everyViewType() {
		got := ViewFromProto(ViewToProto(v))
		if !reflect.DeepEqual(got, v) {
			t.Errorf("%s did not survive:\n want %#v\n  got %#v", name, v, got)
		}
	}
}

// A nil view is legal everywhere one is accepted and means "nothing to show".
// It must not become an error, and an error must not become nothing.
func TestNothingToShowStaysNothingToShow(t *testing.T) {
	if got := ViewFromProto(ViewToProto(nil)); got != nil {
		t.Errorf("a nil view came back as %#v", got)
	}
	if got := ViewFromProto(nil); got != nil {
		t.Errorf("a nil message came back as %#v", got)
	}
	if got := ViewFromProto(&rtav1.View{}); got != nil {
		t.Errorf("an unset oneof came back as %#v", got)
	}
}

// TestEveryViewUnionMemberIsInTheFixture keeps the round-trip test honest.
//
// The round-trip test is only as good as its fixture, and a fixture is a
// hand-written list — so an eighth view type would be added to pkg/view,
// encoded by nothing here, and tested by nothing. view.TypeOf is derived from
// the union itself, so asking it what each fixture entry is and requiring the
// answers to be distinct and complete ties the two together.
func TestEveryViewUnionMemberIsInTheFixture(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range everyViewType() {
		seen[view.TypeOf(v)] = true
	}
	// The union as pkg/view names it. This list is checked against the source
	// by the wire encoder itself: a member missing here would have to be
	// missing from ViewToProto's switch too, which the next assertion catches.
	for _, want := range []string{"text", "keyvalue", "table", "tree", "chart", "sections", "error"} {
		if !seen[want] {
			t.Errorf("view type %q is not in the round-trip fixture", want)
		}
	}
	if len(seen) != 7 {
		t.Errorf("the fixture covers %d view types, not 7: %v", len(seen), seen)
	}
	// And the encoder must actually have a branch for each: a type falling
	// through ViewToProto's switch encodes as "nothing to show", which a
	// round-trip on a *populated* view would catch, so this is belt and
	// braces for the one that is easy to get wrong.
	for name, v := range everyViewType() {
		if ViewToProto(v).Kind == nil {
			t.Errorf("%s encoded to an unset oneof, so ViewToProto has no branch for it", name)
		}
	}
}

// A declaration with every field set to something that is not its zero value,
// for the same reason the view fixture is: an unencoded field round-trips
// perfectly when it is empty on both sides.
func fullDeclaration() plugin.Plugin {
	return plugin.Plugin{
		Name:    "demo",
		Summary: "a demo plugin",
		Version: "1.2.3",
		Needs:   []plugin.Need{plugin.NeedKubeconfig},
		Capabilities: []plugin.Capability{{
			ID:           "demo.thing.get",
			Summary:      "get a thing",
			Description:  "The long form.\n\nWith paragraphs.",
			Safety:       plugin.Destructive,
			Idempotent:   true,
			MinWidth:     44,
			Detailed:     true,
			NoPreview:    true,
			NeedsGrant:   true,
			Scope:        "key",
			HostSpecific: true,
			Inputs: []plugin.Field{
				{
					Name: "key", Type: plugin.String, Help: "which thing",
					Default: "the-default", Required: true, Positional: true,
					Options: []string{"a", "b"},
				},
				{Name: "port", Type: plugin.Int, Help: "port", Default: int64(8080), Min: int64(1), Max: int64(65535),
					Config: "connection.port"},
				{Name: "ratio", Type: plugin.Float, Help: "ratio", Default: 0.5, Min: 0.0, Max: 1.0},
				{Name: "force", Type: plugin.Bool, Help: "force", Default: true},
				{Name: "tags", Type: plugin.StringSlice, Help: "tags", Default: []string{"x", "y"}},
				{Name: "body", Type: plugin.Text, Help: "body"},
				{Name: "file", Type: plugin.Path, Help: "file"},
				{Name: "token", Type: plugin.Secret, Help: "token", Local: true, EnvFallback: true},
				// The address role rather than host/port, because those two
				// are legal only as a pair and this fixture needs one input
				// carrying a non-zero Endpoint, not a connection.
				{Name: "addr", Type: plugin.String, Help: "address", Local: true,
					Config: "connection.addr", Endpoint: plugin.EndpointAddress},
				// Live crosses as data even though the Suggest it marks is a
				// handler: a host that loses this bit would call the plugin's
				// service listing per keystroke.
				{Name: "bucket", Type: plugin.String, Help: "bucket", Live: true},
				// TLSAdjacent needs its own input rather than riding one already
				// declared here: addr already carries a non-zero Endpoint, and
				// TLSAdjacent's own contract is that it carries none.
				{Name: "ca-file", Type: plugin.String, Help: "ca", Local: true, TLSAdjacent: true},
			},
		}},
	}
}

// The declaration is what every surface is built from — flags, form fields,
// dashboard tiles, MCP schemas, grant scoping — so a field that does not
// cross is a plugin that behaves differently from a built-in with the same
// declaration: a second-class plugin, which is the one thing the contract
// must never allow.
func TestTheDeclarationSurvivesARoundTrip(t *testing.T) {
	want := fullDeclaration()
	got, unknown := PluginFromProto(PluginToProto(want))
	if len(unknown) != 0 {
		t.Fatalf("the encoder produced something the decoder could not read: %v", unknown)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the declaration did not survive:\n want %#v\n  got %#v", want, got)
	}
}

// TestEveryDeclarationFieldIsCarried walks the declaration structs and
// asserts the round-trip fixture leaves nothing at its zero value.
//
// This is what makes the round-trip test mean something. Adding a field to
// Capability and forgetting the proto passes a round trip trivially: the
// encoder does not write it, the decoder does not read it, and both sides
// hold the zero value, which compares equal. The fixture having no zero
// values is the property that turns DeepEqual into real coverage, and this
// test is what keeps that true as the structs grow.
func TestEveryDeclarationFieldIsCarried(t *testing.T) {
	p := fullDeclaration()
	check := func(what string, v reflect.Value, exempt map[string]string) {
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			if why, ok := exempt[f.Name]; ok {
				t.Logf("%s.%s is not carried: %s", what, f.Name, why)
				continue
			}
			if v.Field(i).IsZero() {
				t.Errorf("%s.%s is zero in the round-trip fixture, so nothing checks whether it crosses the wire",
					what, f.Name)
			}
		}
	}
	check("Plugin", reflect.ValueOf(p), nil)
	check("Capability", reflect.ValueOf(p.Capabilities[0]), map[string]string{
		// Handlers are what the service's methods are for; the declaration
		// carries only whether the optional ones exist. Setting them in the
		// fixture would make the round trip fail by design, since a decoded
		// declaration has no handlers until the host attaches them.
		"Run":     "a handler, carried as an RPC rather than as data",
		"Prefill": "a handler; has_prefill crosses instead",
	})
	// Across every input rather than the first one. No single Field can hold
	// all of them — Min and Max need a numeric input, Local a secret, Config
	// a non-positional — so checking one input meant carrying an exemption
	// per field that said "checked on another input of the same fixture".
	// Those were four unverified claims about the fixture sitting in the one
	// test whose job is to stop unverified claims about the fixture. Asking
	// whether each field is non-zero on at least one input says the same
	// thing and is a fact rather than a comment.
	checkAcross("Field", p.Capabilities[0].Inputs, map[string]string{
		"Suggest": "a handler; has_suggest crosses instead",
	}, t)
}

// checkAcross asserts every exported field is non-zero on at least one
// element, naming the ones that are zero everywhere.
func checkAcross[T any](what string, items []T, exempt map[string]string, t *testing.T) {
	t.Helper()
	if len(items) == 0 {
		t.Fatalf("%s: the fixture has no items to check", what)
	}
	typ := reflect.TypeOf(items[0])
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if why, ok := exempt[f.Name]; ok {
			t.Logf("%s.%s is not carried: %s", what, f.Name, why)
			continue
		}
		set := false
		for _, item := range items {
			if !reflect.ValueOf(item).Field(i).IsZero() {
				set = true
				break
			}
		}
		if !set {
			t.Errorf("%s.%s is zero on every input in the round-trip fixture, so nothing checks whether it crosses the wire",
				what, f.Name)
		}
	}
}

// has_prefill and has_suggest are how a host learns that calling those RPCs
// would mean anything. Getting them backwards is quiet: the host simply never
// offers edit-in-place or completion, and the plugin author sees a feature
// that does not work with no error anywhere.
func TestHandlerPresenceCrossesEvenThoughHandlersDoNot(t *testing.T) {
	p := fullDeclaration()
	if pb := PluginToProto(p); pb.Capabilities[0].GetHasPrefill() {
		t.Error("has_prefill is set for a capability with no Prefill")
	}
	p.Capabilities[0].Prefill = func(context.Context, plugin.Request) (map[string]any, error) { return nil, nil }
	if pb := PluginToProto(p); !pb.Capabilities[0].GetHasPrefill() {
		t.Error("has_prefill is not set for a capability that has one")
	}
}

// TestEveryViewSurvivesRealSerialization is the same round trip through
// proto.Marshal and proto.Unmarshal rather than through these functions
// alone.
//
// Converting a struct to a struct and back exercises none of the wire: it
// cannot see a field number collide, an int32 truncate, or the empty-versus-
// nil distinction proto3 does not have. A test that passes on the part it can
// see and says nothing about the part it cannot is worse than no test, because
// it is quoted as coverage.
func TestEveryViewSurvivesRealSerialization(t *testing.T) {
	for name, v := range everyViewType() {
		wire, err := proto.Marshal(ViewToProto(v))
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var back rtav1.View
		if err := proto.Unmarshal(wire, &back); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if got := ViewFromProto(&back); !reflect.DeepEqual(got, v) {
			t.Errorf("%s did not survive the wire:\n want %#v\n  got %#v", name, v, got)
		}
	}
}

func TestTheDeclarationSurvivesRealSerialization(t *testing.T) {
	want := fullDeclaration()
	wire, err := proto.Marshal(PluginToProto(want))
	if err != nil {
		t.Fatal(err)
	}
	var back rtav1.Plugin
	if err := proto.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	got, unknown := PluginFromProto(&back)
	if len(unknown) != 0 {
		t.Fatalf("unreadable after the wire: %v", unknown)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the declaration did not survive the wire:\n want %#v\n  got %#v", want, got)
	}
}

// Every Go integer width is one wire integer, and comes back as int64. A
// handler never notices — Request.Int, Request.Float and Resolve read every
// width — and the alternative is nine wire types to preserve a distinction
// nobody can observe.
func TestEveryIntegerWidthCrossesAsOneInteger(t *testing.T) {
	for _, v := range []any{int(7), int8(7), int16(7), int32(7), int64(7),
		uint(7), uint8(7), uint16(7), uint32(7), uint64(7)} {
		if got := ValueFromProto(ValueToProto(v)); got != int64(7) {
			t.Errorf("%T(7) came back as %T(%v), want int64(7)", v, got, got)
		}
	}
	// Beyond what a double can hold exactly, which is the case that rules out
	// google.protobuf.Value and is the reason Value is a hand-written oneof.
	const big = int64(1)<<53 + 1
	if got := ValueFromProto(ValueToProto(big)); got != big {
		t.Errorf("%d came back as %v — the wire is lossy above 2^53", big, got)
	}
}

// Absent and zero are different questions. `--limit 0` says take nothing;
// no --limit at all says use the default. A wire that flattens them makes
// every numeric default unexpressible.
func TestAbsentIsNotZero(t *testing.T) {
	if got := ValueToProto(nil); got != nil {
		t.Errorf("nil encoded as %#v", got)
	}
	if got := ValueFromProto(nil); got != nil {
		t.Errorf("nil decoded as %#v", got)
	}
	for _, zero := range []any{int64(0), 0.0, false, ""} {
		v := ValueToProto(zero)
		if v == nil {
			t.Errorf("%#v encoded as absent", zero)
			continue
		}
		if got := ValueFromProto(v); got != zero {
			t.Errorf("%#v round-tripped to %#v", zero, got)
		}
	}
}

// A bare []any of strings is what an MCP client sends for a string-slice
// input, since JSON has no typed arrays. internal/mcp accepts it and
// Request.StringSlice reads it, so refusing it here would make a plugin
// stricter than a built-in for the identical declaration.
func TestAnUntypedStringListCrosses(t *testing.T) {
	got := ValueFromProto(ValueToProto([]any{"a", "b"}))
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("[]any{\"a\",\"b\"} came back as %#v", got)
	}
	// Something that is not a list of strings has no wire form and must not
	// become one by stringifying: a handler would receive a value its declared
	// type says is impossible.
	if got := ValueToProto([]any{"a", 1}); got != nil {
		t.Errorf("a mixed list encoded as %#v", got)
	}
	if got := ValueToProto(struct{ X int }{1}); got != nil {
		t.Errorf("an arbitrary struct encoded as %#v", got)
	}
}
