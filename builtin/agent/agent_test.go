package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/this-is-tobi/rta/internal/agentlog"
	"github.com/this-is-tobi/rta/internal/consent"
	"github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/policy"
	"github.com/this-is-tobi/rta/internal/session"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// withPolicy puts a team ceiling above the working directory, so alsoGrant's
// clamp has a policy to apply against. Duplicated from builtin/grant's own
// test helper of the same name rather than shared, because it is test-only
// and the two packages do not otherwise depend on each other's tests.
func withPolicy(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policy.RepoFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
}

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("RTA_DATA_DIR", t.TempDir())
}

func capability(t *testing.T, id string) plugin.Capability {
	t.Helper()
	for _, c := range Plugin().Capabilities {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no capability %q", id)
	return plugin.Capability{}
}

func run(t *testing.T, id string, values map[string]any) (view.View, error) {
	t.Helper()
	c := capability(t, id)
	return c.Run(context.Background(), plugin.NewRequest(
		plugin.Resolve(c, plugin.Inputs{Caller: values}), false, false).WithSurface(plugin.SurfaceCLI))
}

func park(t *testing.T, capID string, scopes ...string) consent.Request {
	t.Helper()
	p, err := consent.Ask(consent.Call{
		Cap: capID, Safety: "write", Scopes: scopes,
		Args: map[string]any{"key": "db-password"}, Why: "no active grant",
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p.Request
}

// The rule the whole namespace rests on: none of it answers an agent.
func TestNothingHereAnswersAnAgent(t *testing.T) {
	isolate(t)
	for _, c := range Plugin().Capabilities {
		req := plugin.NewRequest(map[string]any{"id": "x"}, false, false).WithSurface(plugin.SurfaceMCP)
		v, err := c.Run(context.Background(), req)
		if err == nil {
			t.Fatalf("%s answered an MCP caller with %v", c.ID, v)
		}
		ve, ok := err.(*view.Error)
		if !ok || ve.Code != "agent.surface" || !ve.Refusal {
			t.Fatalf("%s refused with %v, want the surface refusal, marked one", c.ID, err)
		}
	}
}

func TestPendingListsWhatIsWaiting(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")
	v, err := run(t, "agent.pending", nil)
	if err != nil {
		t.Fatal(err)
	}
	table, ok := v.(view.Table)
	if !ok {
		t.Fatalf("view = %T", v)
	}
	if len(table.Rows) != 1 {
		t.Fatalf("%d rows, want the one parked call", len(table.Rows))
	}
	row := strings.Join(table.Rows[0], " ")
	for _, want := range []string{r.ID, "kv.get", "db-password"} {
		if !strings.Contains(row, want) {
			t.Fatalf("the row does not carry %q: %s", want, row)
		}
	}
}

func TestShowSaysWhatTheCallWouldDo(t *testing.T) {
	isolate(t)
	p, err := consent.Ask(consent.Call{
		Cap: "todo.rm", Safety: "destructive", Scopes: []string{"4"},
		Args:    map[string]any{"id": 4},
		Why:     "no active grant for todo.rm 4",
		Preview: "would remove task 4: ship the release notes",
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	v, err := run(t, "agent.show", map[string]any{"id": p.Request.ID})
	if err != nil {
		t.Fatal(err)
	}
	secs := v.(view.Sections).Items
	last := secs[len(secs)-1]
	if last.ID != "outcome" {
		t.Fatalf("the last section is %q", last.ID)
	}
	if body := last.View.(view.Text).Body; !strings.Contains(body, "would remove task 4") {
		t.Fatalf("the page does not say what it would do: %q", body)
	}
}

func TestShowSaysWhyThereIsNoPreviewRatherThanNothing(t *testing.T) {
	// Silence would read as "it would do nothing", which is the one thing a
	// missing preview must not be mistaken for.
	isolate(t)
	for _, tc := range []struct {
		name string
		call consent.Call
		want string
	}{
		{"a write call", consent.Call{Cap: "kv.get", Safety: "write"}, "previews destructive calls"},
		{"a profiled call", consent.Call{Cap: "todo.rm", Safety: "destructive", Profile: "prod"},
			"resolves connections only after you answer"},
		{"an external plugin", consent.Call{Cap: "s3.object.rm", Safety: "destructive"},
			"a promise rta cannot check"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := consent.Ask(tc.call, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			v, err := run(t, "agent.show", map[string]any{"id": p.Request.ID})
			if err != nil {
				t.Fatal(err)
			}
			secs := v.(view.Sections).Items
			body := secs[len(secs)-1].View.(view.Text).Body
			if !strings.Contains(body, tc.want) {
				t.Fatalf("body = %q, want it to explain %q", body, tc.want)
			}
		})
	}
}

func TestAllowReleasesExactlyOneCall(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")

	v, err := run(t, "agent.allow", map[string]any{"id": r.ID})
	if err != nil {
		t.Fatal(err)
	}
	kv, ok := v.(view.KeyValue)
	if !ok {
		t.Fatalf("view = %T", v)
	}
	joined := ""
	for _, p := range kv.Pairs {
		joined += p.Key + "=" + p.Value + ";"
	}
	if !strings.Contains(joined, "this call only") {
		t.Fatalf("the answer does not say how far it reaches: %s", joined)
	}
	// No standing state: an allow is about one call.
	grants, verr := grant.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	if len(grants) != 0 {
		t.Fatalf("a plain allow issued %d grants", len(grants))
	}
}

func TestAllowWithATTLAlsoIssuesTheGrantYouWouldHaveTyped(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")

	if _, err := run(t, "agent.allow", map[string]any{"id": r.ID, "ttl": "15m"}); err != nil {
		t.Fatal(err)
	}
	grants, verr := grant.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	if len(grants) != 1 {
		t.Fatalf("%d grants issued, want one", len(grants))
	}
	g := grants[0]
	if g.Target != "kv.get" || g.Scope != "db-password" {
		t.Fatalf("the grant does not match the call: %+v", g)
	}
	if d := time.Until(g.Expires); d > 16*time.Minute || d < 14*time.Minute {
		t.Fatalf("the grant lasts %s, want about 15m", d)
	}
}

// alsoGrant issues a standing grant through the same internal/grant.Issue
// path `rta grant allow` uses, so it has to apply the same ceiling —
// otherwise a team policy tightening the window did nothing here, while
// internal/grant.Load() went on enforcing it on every read regardless,
// silently expiring the grant far earlier than the answer just given here
// promised, with nothing saying so.
func TestAllowWithATTLAppliesTheTeamCeilingAndSaysSo(t *testing.T) {
	isolate(t)
	withPolicy(t, "maxTTL: 15m\n")
	r := park(t, "kv.get", "db-password")

	v, err := run(t, "agent.allow", map[string]any{"id": r.ID, "ttl": "4h"})
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, p := range v.(view.KeyValue).Pairs {
		joined += p.Key + "=" + p.Value + ";"
	}
	if !strings.Contains(joined, "capped") || !strings.Contains(joined, "team's policy") {
		t.Fatalf("the answer did not say the grant was capped by the team's policy: %s", joined)
	}
	if !strings.Contains(joined, policy.RepoFile) {
		t.Fatalf("the answer did not name the policy file: %s", joined)
	}

	grants, verr := grant.Load()
	if verr != nil {
		t.Fatal(verr)
	}
	if len(grants) != 1 {
		t.Fatalf("%d grants issued, want one", len(grants))
	}
	if window := grants[0].Expires.Sub(grants[0].Issued); window > 16*time.Minute {
		t.Fatalf("the stored grant lasts %s, want about 15m — the policy ceiling did not apply", window)
	}
}

// The bare "this call only" answer is the one place a live approval actually
// executes the capability — see the comment beside grant.CheckCeiling in
// runAllow. A `never` rule is documented as needing nobody's agreement, so it
// has to stop this exactly as it already stops alsoGrant's --ttl branch,
// tested above.
func TestAllowIsRefusedWhenTheTeamCeilingForbidsTheTarget(t *testing.T) {
	isolate(t)
	withPolicy(t, "never:\n  - kv.get\n")
	r := park(t, "kv.get", "db-password")

	_, err := run(t, "agent.allow", map[string]any{"id": r.ID})
	if err == nil {
		t.Fatal("a ceiling-forbidden target was allowed")
	}
	ve, ok := err.(*view.Error)
	if !ok || ve.Code != "grant.policy.refused" {
		t.Fatalf("refused with %v, want the policy refusal", err)
	}

	// Refused, not silently consumed: the request is still there, exactly as
	// if nobody had answered it yet, so `agent pending` still shows it.
	if _, ok := consent.Find(r.ID); !ok {
		t.Fatal("the parked request was consumed by a refused approval")
	}
}

func TestATTLIsRefusedWhenNoSingleGrantWouldCoverTheCall(t *testing.T) {
	isolate(t)
	// Two records in one call: a standing grant either misses one or
	// widens to the whole capability, and widening is not what --ttl asked
	// for.
	r := park(t, "kv.get", "db-password", "prod-token")
	v, err := run(t, "agent.allow", map[string]any{"id": r.ID, "ttl": "15m"})
	if err != nil {
		t.Fatal(err)
	}
	kv := v.(view.KeyValue)
	joined := ""
	for _, p := range kv.Pairs {
		joined += p.Key + "=" + p.Value + ";"
	}
	if !strings.Contains(joined, "not issued") {
		t.Fatalf("a multi-record --ttl said nothing about the grant: %s", joined)
	}
	// The call itself is still allowed — the operator answered the
	// question they were asked.
	if !strings.Contains(joined, "allowed=") {
		t.Fatalf("the call was not allowed: %s", joined)
	}
	grants, _ := grant.Load()
	if len(grants) != 0 {
		t.Fatalf("a grant was issued anyway: %+v", grants)
	}
}

func TestABadTTLDoesNotUndoTheAnswer(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")
	v, err := run(t, "agent.allow", map[string]any{"id": r.ID, "ttl": "sometime"})
	if err != nil {
		t.Fatalf("a bad --ttl lost the whole answer: %v", err)
	}
	joined := ""
	for _, p := range v.(view.KeyValue).Pairs {
		joined += p.Value + ";"
	}
	if !strings.Contains(joined, "not issued") {
		t.Fatalf("the failure was not reported: %s", joined)
	}
}

func TestDenyIsAnAnswer(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")
	if _, err := run(t, "agent.deny", map[string]any{"id": r.ID}); err != nil {
		t.Fatal(err)
	}
}

func TestAnswerAnUnknownRequestNamesWhatIsWaiting(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")
	_, err := run(t, "agent.allow", map[string]any{"id": "nosuch"})
	ve, ok := err.(*view.Error)
	if !ok || ve.Code != "agent.request.unknown" {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(ve.Hint, r.ID) {
		t.Fatalf("the hint does not name what is waiting: %s", ve.Hint)
	}
}

// rewrite doctors a parked request the way something with a write into rta's
// data directory would: the display becomes harmless, the digest that binds
// the real call is left exactly where it was found.
func rewrite(t *testing.T, id string, edit func(map[string]any)) {
	t.Helper()
	path := filepath.Join(consent.Dir(), id+".request.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestARewrittenRequestIsRefusedAsOneRatherThanAsAStaleID(t *testing.T) {
	// consent.Scan keeps it off every queue, so all three of these refuse it
	// whatever they do next. What is being pinned here is the *sentence*: an
	// operator told "no request is waiting" shrugs at a stale id, and the
	// thing they needed to learn is that something on their machine is
	// writing into rta's data directory to make them approve one call while
	// reading another.
	isolate(t)
	r := park(t, "kv.get", "db-password")
	rewrite(t, r.ID, func(doc map[string]any) {
		doc["capability"] = "sys.cpu"
		doc["safety"] = "read"
		doc["scopes"] = []string{}
		doc["args"] = map[string]any{}
		doc["preview"] = "would report the current CPU load"
	})
	for _, id := range []string{"agent.show", "agent.allow", "agent.deny"} {
		_, err := run(t, id, map[string]any{"id": r.ID})
		ve, ok := err.(*view.Error)
		if !ok || ve.Code != "agent.request.tampered" {
			t.Fatalf("%s answered a rewritten request with %v", id, err)
		}
		if !strings.Contains(ve.Hint, "rewrote it") {
			t.Fatalf("%s does not say what happened: %s", id, ve.Hint)
		}
	}
	// And it is gone from the list a person reads, rather than sitting there
	// looking answerable.
	v, err := run(t, "agent.pending", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rows := v.(view.Table).Rows; len(rows) != 0 {
		t.Fatalf("the rewritten request is still listed: %v", rows)
	}
}

func TestAnUnknownIDIsStillJustAnUnknownID(t *testing.T) {
	// The other half: the sharp message must not start firing for the
	// ordinary case of an id that expired or was already answered.
	isolate(t)
	park(t, "kv.get", "db-password")
	_, err := run(t, "agent.allow", map[string]any{"id": "nosuch"})
	ve, ok := err.(*view.Error)
	if !ok || ve.Code != "agent.request.unknown" {
		t.Fatalf("err = %v, want the plain unknown-id refusal", err)
	}
}

func TestDryRunAnswersNothing(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")
	c := capability(t, "agent.allow")
	req := plugin.NewRequest(map[string]any{"id": r.ID}, true, false).WithSurface(plugin.SurfaceCLI)
	if _, err := c.Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// Still waiting: a preview must not answer for the operator.
	if _, ok := consent.Find(r.ID); !ok {
		t.Fatal("--dry-run answered the request")
	}
}

func TestALostCallIsShownOnTheRowThatFollowsIt(t *testing.T) {
	// The gap has a position. An operator reading down the "why" column to
	// find out what happened at a given minute has to be able to see that
	// something at that minute is missing, rather than find it in a footnote
	// under the table.
	isolate(t)
	if err := agentlog.Append(agentlog.Entry{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open}); err != nil {
		t.Fatal(err)
	}
	appendRaw(t, `{"seq":2,"at":"2026-08-28T00:00:00Z","capability":"kv.get","outcome":"ran","auth":"open","missed":2,"prev":"x","seal":"y"}`)

	v, err := run(t, "agent.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	rows := v.(view.Table).Rows
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	if why := cell(t, v.(view.Table), 1, "why"); !strings.Contains(why, "2 calls before this one could not be recorded") {
		t.Fatalf("the row does not admit the gap: %q", why)
	}
	// One is singular, and a row with nothing missing says nothing.
	if got := whyLine(agentlog.Entry{Missed: 1}); !strings.Contains(got, "1 call before") {
		t.Fatalf("whyLine(1) = %q", got)
	}
	if got := whyLine(agentlog.Entry{Reason: "core.grant.required: no grant"}); got != "core.grant.required: no grant" {
		t.Fatalf("a clean row grew a note: %q", got)
	}
}

func TestTheDetailedLogSaysWhenHistoryWasRetired(t *testing.T) {
	// A reader who is not told that history was dropped reads "no calls
	// before the 14th" as "nothing happened before the 14th", which is the
	// one misreading a record must not invite.
	// Against the report rather than against a real rotation: what is being
	// checked here is the sentence, and internal/agentlog is where rotation
	// itself is proven.
	joined := ""
	for _, p := range recordPairs(agentlog.Report{
		Entries: 12000, Size: 40 << 20, Files: 4,
		Retired: 30000, RetiredAt: time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC),
	}, nil) {
		joined += p.Key + "=" + p.Value + ";"
	}
	for _, want := range []string{"retired=", "the first 30000 calls", "files=4", "chain=whole"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the record's own description is missing %q: %s", want, joined)
		}
	}
	// And a record that has lost nothing says nothing about retirement, or
	// the line becomes noise every reader learns to skip.
	quiet := ""
	for _, p := range recordPairs(agentlog.Report{Entries: 12, Size: 3000, Files: 1}, nil) {
		quiet += p.Key + "=" + p.Value + ";"
	}
	if strings.Contains(quiet, "retired") || strings.Contains(quiet, "files=") {
		t.Fatalf("a whole record volunteered retention detail: %s", quiet)
	}
}

func TestTheLogShowsCallsAndVerifiesItsOwnChain(t *testing.T) {
	isolate(t)
	for _, e := range []agentlog.Entry{
		{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open},
		{Cap: "kv.get", Args: map[string]any{"key": "db"}, Outcome: agentlog.Refused,
			Auth: agentlog.Blocked, Reason: "core.grant.required: no active grant"},
	} {
		if err := agentlog.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	v, err := run(t, "agent.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	table := v.(view.Table)
	if len(table.Rows) != 2 {
		t.Fatalf("%d rows", len(table.Rows))
	}
	// Time order, newest last: a log is read from its end, back.
	if got := cell(t, table, 1, "capability"); got != "kv.get" {
		t.Fatalf("rows are not oldest-first: %v", table.Rows)
	}
	if !table.Tail {
		t.Error("the log must say its newest row is last, so a scrolling surface opens there")
	}

	// --refused filters to what rta would not do.
	v, err = run(t, "agent.log", map[string]any{"refused": true})
	if err != nil {
		t.Fatal(err)
	}
	if tbl := v.(view.Table); len(tbl.Rows) != 1 || cell(t, tbl, 0, "capability") != "kv.get" {
		t.Fatalf("--refused = %v", tbl.Rows)
	}

	// --detail carries the integrity verdict.
	v, err = run(t, "agent.log", map[string]any{"detail": true})
	if err != nil {
		t.Fatal(err)
	}
	secs := v.(view.Sections)
	integrity := ""
	for _, p := range secs.Items[1].View.(view.KeyValue).Pairs {
		integrity += p.Key + "=" + p.Value + ";"
	}
	if !strings.Contains(integrity, "whole") {
		t.Fatalf("a good chain did not read as whole: %s", integrity)
	}
}

func TestTheLogShowsTheCodeAsItsOwnColumn(t *testing.T) {
	isolate(t)
	for _, e := range []agentlog.Entry{
		{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open},
		{Cap: "kv.get", Outcome: agentlog.Refused, Auth: agentlog.Blocked,
			Code: "core.grant.required", Reason: "no active grant"},
	} {
		if err := agentlog.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	v, err := run(t, "agent.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	table := v.(view.Table)
	if got := cell(t, table, 1, "code"); got != "core.grant.required" {
		t.Fatalf("code column = %q, want the dotted code alone", got)
	}
	if got := cell(t, table, 1, "why"); got != "no active grant" {
		t.Fatalf("why column = %q, want the sentence without the code", got)
	}
	// Blank rather than an em dash on the row where nothing went wrong,
	// matching why: code and why are the two halves of one cause, and a
	// clean row has neither.
	if got := cell(t, table, 0, "code"); got != "" {
		t.Fatalf("code column on a clean row = %q, want blank", got)
	}

	// Same rule as agent and credential: a record with no coded row — one
	// written before the code/reason split, or one where nothing has gone
	// wrong — grows no column at all.
	isolate(t)
	if err := agentlog.Append(agentlog.Entry{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open}); err != nil {
		t.Fatal(err)
	}
	v, err = run(t, "agent.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.(view.Table).Columns {
		if c.Name == "code" {
			t.Fatal("code column appeared with nothing to fill it")
		}
	}
}

func TestTheLogShowsWhichCredentialAuthenticatedEachCall(t *testing.T) {
	isolate(t)
	for _, e := range []agentlog.Entry{
		{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open},
		{Cap: "kv.get", Outcome: agentlog.Ran, Auth: agentlog.Open, Credential: "gateway-token"},
	} {
		if err := agentlog.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	v, err := run(t, "agent.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	table := v.(view.Table)
	// Newest last: the credentialed call was appended last.
	if got := cell(t, table, 1, "credential"); got != "gateway-token" {
		t.Fatalf("credential column = %q, want the token label", got)
	}
	if got := cell(t, table, 0, "credential"); got != "—" {
		t.Fatalf("credential column for a stdio call = %q, want the placeholder", got)
	}

	// The column disappears entirely when nothing on this connection ever
	// carried a bearer credential — the same rule the "agent" column
	// already follows, so a quiet stdio-only server does not grow a column
	// of dashes nobody can fill.
	isolate(t)
	if err := agentlog.Append(agentlog.Entry{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open}); err != nil {
		t.Fatal(err)
	}
	v, err = run(t, "agent.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.(view.Table).Columns {
		if c.Name == "credential" {
			t.Fatal("credential column appeared with nothing to fill it")
		}
	}
}

func TestOverviewCountsWhatMatters(t *testing.T) {
	isolate(t)
	park(t, "kv.get", "db-password")
	for _, e := range []agentlog.Entry{
		{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open},
		{Cap: "kv.get", Outcome: agentlog.Refused, Auth: agentlog.Blocked},
		{Cap: "kv.get", Outcome: agentlog.Ran, Auth: agentlog.Live},
	} {
		if err := agentlog.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	v, err := run(t, "agent.overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range v.(view.KeyValue).Pairs {
		got[p.Key] = p.Value
	}
	// The count, and what to press — the tile is where somebody finds out
	// there is a queue at all.
	if got["waiting on you"] != "1 — press w to answer" {
		t.Fatalf("waiting = %q", got["waiting on you"])
	}
	if got["calls in the last hour"] != "3" {
		t.Fatalf("recent = %q", got["calls in the last hour"])
	}
	if got["refused"] != "1" {
		t.Fatalf("refused = %q", got["refused"])
	}
	if got["you approved live"] != "1" {
		t.Fatalf("approved = %q", got["you approved live"])
	}
}

func TestOverviewOnAQuietMachineSaysSo(t *testing.T) {
	isolate(t)
	v, err := run(t, "agent.overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range v.(view.KeyValue).Pairs {
		if p.Key == "last call" && !strings.Contains(p.Value, "nothing recorded") {
			t.Fatalf("last call = %q", p.Value)
		}
		// And an empty queue asks for nothing: a tile that tells you to press
		// a key when there is nothing behind it is a tile you stop reading.
		if p.Key == "waiting on you" && p.Value != "0" {
			t.Fatalf("waiting = %q on a machine with nothing parked", p.Value)
		}
	}
}

func TestTheDetailedOverviewReportsABrokenChain(t *testing.T) {
	isolate(t)
	if err := agentlog.Append(agentlog.Entry{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open}); err != nil {
		t.Fatal(err)
	}
	// Tamper: append a line that cannot verify.
	appendRaw(t, `{"seq":2,"at":"2026-08-28T00:00:00Z","capability":"kv.get","outcome":"ran","auth":"open","prev":"","seal":"beef"}`)

	v, err := run(t, "agent.overview", map[string]any{"detail": true})
	if err != nil {
		t.Fatal(err)
	}
	ledger := ""
	for _, sec := range v.(view.Sections).Items {
		if sec.ID != "ledger" {
			continue
		}
		for _, p := range sec.View.(view.KeyValue).Pairs {
			ledger += p.Key + "=" + p.Value + ";"
		}
	}
	// The same words the page uses: the tile and `agent log --detail` share
	// one description of the record, so they cannot come to disagree about
	// what "intact" means.
	if !strings.Contains(ledger, "BROKEN at entry 2") {
		t.Fatalf("a tampered ledger read as fine: %s", ledger)
	}
}

// appendRaw writes a line straight into the ledger, which is what a tamper
// looks like: bytes appended by something that is not agentlog.Append.
// The one agreement between this file and internal/render/tui: a row action
// takes the record's identity from the first column, so the pending table's
// first column has to be the input agent.allow and agent.deny name. Nothing
// else checks it, and reordering the columns for looks would silently aim
// every TUI answer at a capability name instead of a request id.
func TestTheFirstColumnIsTheIdAnAnswerIsAimedBy(t *testing.T) {
	isolate(t)
	r := park(t, "kv.get", "db-password")
	v, err := run(t, "agent.pending", nil)
	if err != nil {
		t.Fatal(err)
	}
	table := v.(view.Table)
	if len(table.Columns) == 0 || table.Columns[0].Name != "id" {
		t.Fatalf("the first column is %+v, want the request id", table.Columns)
	}
	if len(table.Rows) != 1 || table.Rows[0][0] != r.ID {
		t.Fatalf("the first cell is %q, want the request id %q", table.Rows[0][0], r.ID)
	}
	for _, id := range []string{"agent.allow", "agent.deny"} {
		c := capability(t, id)
		var positional string
		for _, f := range c.Inputs {
			if f.Positional && f.Required {
				positional = f.Name
				break
			}
		}
		if positional != "id" {
			t.Fatalf("%s takes %q positionally, not the %q the table's first column holds",
				id, positional, "id")
		}
	}
}

func TestArgumentsAreCutOnACharacterAndNotOnAByte(t *testing.T) {
	// The arguments column shows text an agent chose, in the table a person
	// reads while deciding whether to allow the call. A byte-wise cut through
	// anything but ASCII ends that cell in a replacement character, which is
	// a mystery exactly where there should be none.
	// Every key length and both rune widths: where a byte-wise cut lands
	// depends on how much ASCII precedes the text, so a single case passes by
	// luck as often as by correctness — this test did, until a probe said so.
	for _, text := range []string{strings.Repeat("é", 100), strings.Repeat("日", 100)} {
		for n := 1; n <= 6; n++ {
			key := strings.Repeat("k", n)
			got := argsLine(map[string]any{key: text})
			if !strings.HasSuffix(got, "…") {
				t.Fatalf("key %q: a long argument was not truncated: %q", key, got)
			}
			if strings.ContainsRune(got, '�') || !utf8.ValidString(got) {
				t.Fatalf("key %q: the cut landed inside a character: %q", key, got)
			}
			if c := utf8.RuneCountInString(got); c > 60 {
				t.Fatalf("key %q: argsLine returned %d characters, cap is 60", key, c)
			}
		}
	}
	// Short lines are left exactly as they are, accents and all.
	if got := argsLine(map[string]any{"k": "café"}); got != "k=café" {
		t.Fatalf("a short line was mangled: %q", got)
	}
}

func appendRaw(t *testing.T, line string) {
	t.Helper()
	f, err := os.OpenFile(agentlog.Path(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// cell reads one column of one row by name.
//
// By name and not by index because these tests were written against the
// index, and adding a `seq` column at the front broke four of them at once
// while the code under test was correct. A test that has to be renumbered
// when a column moves is a test that stops being run.
func cell(t *testing.T, tbl view.Table, row int, column string) string {
	t.Helper()
	for i, c := range tbl.Columns {
		if c.Name == column {
			if row >= len(tbl.Rows) || i >= len(tbl.Rows[row]) {
				t.Fatalf("no cell at row %d column %q", row, column)
			}
			return tbl.Rows[row][i]
		}
	}
	t.Fatalf("no column %q in %v", column, tbl.Columns)
	return ""
}

// Presence is the row the ledger cannot fill: a client attached and not
// calling looks like nothing until something says it is there.
func TestTheOverviewNamesWhoIsConnectedNow(t *testing.T) {
	isolate(t)
	v, err := run(t, "agent.overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := overviewPair(t, v, "connected now"); !strings.HasPrefix(got, "none") {
		t.Fatalf("connected now with nothing open = %q", got)
	}
	id := session.NewID()
	if err := session.Start(session.Record{ID: id, Agent: "claude", Client: "Claude Code 2.1", Since: time.Now(), PID: os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := agentlog.Append(agentlog.Entry{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open, Agent: "claude", Session: id}); err != nil {
			t.Fatal(err)
		}
	}
	v, err = run(t, "agent.overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := overviewPair(t, v, "connected now"); got != "1 — claude (2 calls)" {
		t.Errorf("connected now = %q", got)
	}
	// The detail page carries what the tile leaves out.
	v, err = run(t, "agent.overview", map[string]any{"detail": true})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range v.(view.Sections).Items {
		if s.ID != "connected" {
			continue
		}
		found = true
		table := s.View.(view.Table)
		if len(table.Rows) != 1 || cell(t, table, 0, "client") != "Claude Code 2.1" || cell(t, table, 0, "session") != id || cell(t, table, 0, "calls") != "2" {
			t.Errorf("connected table = %v", table.Rows)
		}
	}
	if !found {
		t.Error("no Connected now section on the detail page")
	}
}

func TestTheLogNarrowsToOneSession(t *testing.T) {
	isolate(t)
	for _, e := range []agentlog.Entry{
		{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open, Agent: "claude", Session: "aaaa0001"},
		{Cap: "kv.get", Outcome: agentlog.Ran, Auth: agentlog.Open, Agent: "claude", Session: "bbbb0002"},
		{Cap: "sys.mem", Outcome: agentlog.Ran, Auth: agentlog.Open, Agent: "claude", Session: "aaaa0001"},
	} {
		if err := agentlog.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	v, err := run(t, "agent.log", map[string]any{"session": "aaaa0001"})
	if err != nil {
		t.Fatal(err)
	}
	table := v.(view.Table)
	if len(table.Rows) != 2 {
		t.Fatalf("rows = %v, want the two calls of that session", table.Rows)
	}
	if got := cell(t, table, 0, "session"); got != "aaaa0001" {
		t.Errorf("session column = %q", got)
	}
	if got := cell(t, table, 1, "capability"); got != "sys.mem" {
		t.Errorf("newest last: capability = %q", got)
	}
}

func overviewPair(t *testing.T, v view.View, key string) string {
	t.Helper()
	kv, ok := v.(view.KeyValue)
	if !ok {
		t.Fatalf("overview is %T, want a KeyValue", v)
	}
	for _, p := range kv.Pairs {
		if p.Key == key {
			return p.Value
		}
	}
	t.Fatalf("no %q row in %v", key, kv.Pairs)
	return ""
}
