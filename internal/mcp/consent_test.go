package mcp

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/this-is-tobi/rta/internal/agentlog"
	"github.com/this-is-tobi/rta/internal/config"
	"github.com/this-is-tobi/rta/internal/consent"
	"github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/profile"
	"github.com/this-is-tobi/rta/internal/registry"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// The two halves of just-in-time consent through the real bridge: a call that parks
// until a person answers, and the record that is written whatever happens.

// answerWhenAsked plays the operator in another process: it waits for a
// request to appear and decides it.
func answerWhenAsked(t *testing.T, allow bool) chan consent.Request {
	t.Helper()
	seen := make(chan consent.Request, 1)
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			pending, err := consent.Pending()
			if err == nil && len(pending) > 0 {
				select {
				case seen <- pending[0]:
				default:
				}
				if err := consent.Decide(pending[0].ID, allow, "test"); err != nil {
					t.Errorf("Decide: %v", err)
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("no request was ever parked")
	}()
	return seen
}

func TestAParkedCallProceedsOnTheOperatorsWord(t *testing.T) {
	s := connect(t, Options{
		AllowWrite:  []string{"demo"},
		Consent:     true,
		ConsentWait: 20 * time.Second,
	})
	seen := answerWhenAsked(t, true)

	res := callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"})
	if res.IsError {
		t.Fatalf("an approved call was still refused: %s", res.Content[0].(*sdk.TextContent).Text)
	}
	select {
	case req := <-seen:
		if req.Cap != "demo.item.reveal" {
			t.Fatalf("the operator was asked about %q", req.Cap)
		}
		if req.Safety != "write" {
			t.Fatalf("the prompt did not carry the stakes: %+v", req)
		}
		if req.Args["key"] != "db-password" {
			t.Fatalf("the prompt did not carry the arguments: %+v", req.Args)
		}
		if req.Why == "" {
			t.Fatal("the prompt did not say why it is being asked")
		}
		if len(req.Scopes) != 1 || req.Scopes[0] != "db-password" {
			t.Fatalf("the prompt did not name the record: %v", req.Scopes)
		}
	default:
		t.Fatal("the call succeeded without anybody being asked")
	}

	// Nothing standing was created: consent is per call.
	entries, err := agentlog.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("the ledger holds %d entries", len(entries))
	}
	if entries[0].Auth != agentlog.Live || entries[0].Outcome != agentlog.Ran {
		t.Fatalf("the ledger misrecords the approval: %+v", entries[0])
	}
}

func TestADeclinedCallIsRefusedWithTheOperatorsAnswer(t *testing.T) {
	s := connect(t, Options{
		AllowWrite:  []string{"demo"},
		Consent:     true,
		ConsentWait: 20 * time.Second,
	})
	answerWhenAsked(t, false)

	res := callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"})
	if !res.IsError {
		t.Fatal("a declined call went through")
	}
	// The agent is told the decision, not the question it was refused
	// before the question was put — and not handed the self-grant command.
	text := res.Content[0].(*sdk.TextContent).Text
	if !strings.Contains(text, "core.consent.declined") || strings.Contains(text, "rta grant allow") {
		t.Fatalf("a declined call was not reported as declined: %s", text)
	}
	entries, _ := agentlog.Read(0)
	if len(entries) != 1 || entries[0].Auth != agentlog.Denied {
		t.Fatalf("the ledger does not record the decline: %+v", entries)
	}
	// The decline is the ledger's own event and carries its own stable code
	// — it used to be the one refusal recorded as bare prose.
	if entries[0].Code != "core.consent.declined" {
		t.Fatalf("the decline's code: %+v", entries[0])
	}
}

func TestNobodyAnsweringRefusesExactlyAsBefore(t *testing.T) {
	// The degradation promise: with consent on and nobody there, the agent
	// gets the same refusal it would have got with consent off.
	s := connect(t, Options{
		AllowWrite:  []string{"demo"},
		Consent:     true,
		ConsentWait: 300 * time.Millisecond,
	})
	res := callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"})
	if !res.IsError {
		t.Fatal("a call nobody answered went through")
	}
	text := res.Content[0].(*sdk.TextContent).Text
	if !strings.Contains(text, "core.grant.required") {
		t.Fatalf("the refusal changed shape: %s", text)
	}
	if !strings.Contains(text, "rta grant allow") {
		t.Fatalf("the refusal lost its hint: %s", text)
	}
	// And the request is not left behind for somebody to answer later.
	pending, _ := consent.Pending()
	if len(pending) != 0 {
		t.Fatalf("%d requests outlived the call", len(pending))
	}
	// The agent sees the unchanged refusal above; the ledger tells the
	// operator what actually happened, under the expiry's own code rather
	// than the question's.
	entries, _ := agentlog.Read(0)
	if len(entries) != 1 || entries[0].Code != "core.consent.expired" ||
		entries[0].Outcome != agentlog.Refused {
		t.Fatalf("the expiry is misrecorded: %+v", entries)
	}
}

func TestAFullQueueRefusesAtOnceInsteadOfAskingAgain(t *testing.T) {
	// Consent fatigue, through the bridge. Once the queue is full the agent
	// gets the refusal it would have got with consent off — immediately,
	// without adding a ninth question to a list nobody can read any more.
	s := connect(t, Options{
		AllowWrite:  []string{"demo"},
		Consent:     true,
		ConsentWait: 30 * time.Second,
	})
	var filled []*consent.Parked
	for i := 0; i < consent.MaxParked; i++ {
		p, err := consent.Ask(consent.Call{Cap: "demo.item.reveal", Safety: "write"}, time.Minute)
		if err != nil {
			t.Fatalf("filling the queue: %v", err)
		}
		filled = append(filled, p)
	}
	defer func() {
		for _, p := range filled {
			p.Close()
		}
	}()

	start := time.Now()
	res := callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"})
	if !res.IsError {
		t.Fatal("a call went through while the queue was full")
	}
	// It must not have parked and waited: the whole point is that the
	// operator is not asked at all.
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("the call waited %s rather than being refused", waited)
	}
	if text := res.Content[0].(*sdk.TextContent).Text; !strings.Contains(text, "core.grant.required") {
		t.Fatalf("the refusal changed shape when the queue was full: %s", text)
	}
	if pending, _ := consent.Pending(); len(pending) != consent.MaxParked {
		t.Fatalf("the queue holds %d requests, want the %d it was filled with",
			len(pending), consent.MaxParked)
	}
	// And the record says the gate refused it, not that anybody declined.
	entries, err := agentlog.Read(0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ledger: %v %d entries", err, len(entries))
	}
	if entries[0].Auth != agentlog.Blocked || entries[0].Code != "core.grant.required" {
		t.Fatalf("the ledger misrecords a refusal nobody was asked about: %+v", entries[0])
	}
}

// Propose-then-approve: a destructive request carries
// what running it would actually do, so the answer is about an outcome.

func TestADestructiveRequestCarriesWhatItWouldDo(t *testing.T) {
	s := connect(t, Options{
		AllowDestructive: []string{"demo.item.rm"},
		Consent:          true,
		ConsentPreview:   true,
		ConsentWait:      20 * time.Second,
	})
	seen := answerWhenAsked(t, false)
	callTool(t, s, "demo_item_rm", map[string]any{"name": "invoices"})
	select {
	case req := <-seen:
		if !strings.Contains(req.Preview, "would remove item invoices") {
			t.Fatalf("the request does not say what it would do: %q", req.Preview)
		}
		// The preview is the capability's own words about *this* call, so it
		// carries the consequence the arguments alone do not show.
		if !strings.Contains(req.Preview, "3 things filed under it") {
			t.Fatalf("the preview lost the part worth reading: %q", req.Preview)
		}
	default:
		t.Fatal("nothing was parked")
	}
}

func TestThePreviewIsDisplayAndNotTheBinding(t *testing.T) {
	// Same rule as the rest of the request, and it matters most here: a
	// preview is the most persuasive thing in the file. Rewriting it changes
	// what somebody is told, never what they authorize.
	a := consent.Call{Cap: "demo.item.rm", Safety: "destructive",
		Args: map[string]any{"name": "invoices"}, Preview: "would remove item invoices"}
	b := a
	b.Preview = "would do nothing at all, this is completely safe"
	if a.Digest() != b.Digest() {
		t.Fatal("the preview is part of the binding, so a rewritten one would invalidate the approval " +
			"instead of merely misleading — and the operator would see a request that cannot be answered")
	}
}

func TestOnlyDestructiveCallsArePreviewed(t *testing.T) {
	// A preview is an extra invocation of the handler, worth it where the
	// answer is irreversible and not otherwise.
	s := connect(t, Options{
		AllowWrite:     []string{"demo"},
		Consent:        true,
		ConsentPreview: true,
		ConsentWait:    20 * time.Second,
	})
	seen := answerWhenAsked(t, false)
	callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"})
	select {
	case req := <-seen:
		if req.Preview != "" {
			t.Fatalf("a write call was previewed: %q", req.Preview)
		}
	default:
		t.Fatal("nothing was parked")
	}
}

func TestWithPreviewOffNothingRunsBeforeTheAnswer(t *testing.T) {
	// The off switch has to mean it: with --consent-preview=false the
	// handler is not touched until the operator says yes.
	for _, tc := range []struct {
		name     string
		preview  bool
		wantRuns int32
	}{
		{"off", false, 0},
		{"on", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dryRuns atomic.Int32
			reg := registry.New()
			if err := reg.Register(plugin.Plugin{
				Name: "demo", Summary: "counts its own dry runs",
				Capabilities: []plugin.Capability{{
					ID: "demo.item.rm", Summary: "remove item", Safety: plugin.Destructive,
					Scope:  "name",
					Inputs: []plugin.Field{{Name: "name", Type: plugin.String, Help: "which item"}},
					Run: func(_ context.Context, req plugin.Request) (view.View, error) {
						if req.DryRun {
							dryRuns.Add(1)
							return view.Text{Body: "would remove " + req.String("name")}, nil
						}
						return view.Text{Body: "removed"}, nil
					},
				}},
			}); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RTA_DATA_DIR", t.TempDir())
			s := connectWith(t, reg, Options{
				AllowDestructive: []string{"demo.item.rm"},
				Consent:          true,
				ConsentPreview:   tc.preview,
				ConsentWait:      500 * time.Millisecond,
			})
			callTool(t, s, "demo_item_rm", map[string]any{"name": "invoices"})
			if got := dryRuns.Load(); got != tc.wantRuns {
				t.Fatalf("the handler was dry-run %d times with preview %v, want %d",
					got, tc.preview, tc.wantRuns)
			}
		})
	}
}

func TestAnExternalPluginIsNeverRunToProduceAPreview(t *testing.T) {
	// The bound that *is* this feature. A dry run is an extra invocation of
	// the handler, and on a request the operator goes on to deny it is an
	// invocation that would never otherwise have happened — so it rests on
	// the handler being honest about DryRun, which rta can vouch for in its
	// own code and cannot in anybody else's. The assertion is therefore not
	// "the preview is empty" but "the plugin was not called at all".
	var touched atomic.Int32
	reg := registry.New()
	p := plugin.Plugin{
		Name: "hello", Summary: "an external plugin",
		Capabilities: []plugin.Capability{{
			ID: "hello.wipe", Summary: "wipe it", Safety: plugin.Destructive,
			Scope:  "name",
			Inputs: []plugin.Field{{Name: "name", Type: plugin.String, Help: "what"}},
			Run: func(_ context.Context, req plugin.Request) (view.View, error) {
				touched.Add(1)
				if req.DryRun {
					return view.Text{Body: "would wipe " + req.String("name")}, nil
				}
				return view.Text{Body: "wiped"}, nil
			},
		}},
	}
	origin := registry.Origin{Path: "/usr/local/bin/rta-plugin-hello", Digest: "5dae737f8845"}
	if err := reg.RegisterFrom(p, origin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	s := connectWith(t, reg, Options{
		// The digest pin an external destructive capability requires.
		AllowDestructive: []string{"hello.wipe@5dae737f8845"},
		Origin:           reg.Origin,
		Consent:          true,
		ConsentPreview:   true,
		ConsentWait:      600 * time.Millisecond,
	})
	seen := make(chan consent.Request, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if pending, err := consent.Pending(); err == nil && len(pending) > 0 {
				seen <- pending[0]
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	callTool(t, s, "hello_wipe", map[string]any{"name": "everything"})

	select {
	case req := <-seen:
		if req.Preview != "" {
			t.Fatalf("an external plugin's request carried a preview: %q", req.Preview)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing was parked, so this proves nothing")
	}
	if n := touched.Load(); n != 0 {
		t.Fatalf("the external plugin ran %d times for a call nobody approved", n)
	}
}

func TestAProfiledCallIsNotPreviewedAgainstTheWrongPlace(t *testing.T) {
	// Connections resolve after consent, deliberately, so that an unknown
	// profile and an ungranted one give the same refusal. A dry run at this
	// point would therefore run with no connection at all and describe the
	// wrong place convincingly — and the whole job of a preview is to be
	// believed.
	var previews atomic.Int32
	reg := registry.New()
	if err := reg.Register(plugin.Plugin{
		Name: "pg", Summary: "a profilable plugin",
		Capabilities: []plugin.Capability{{
			ID: "pg.drop", Summary: "drop a table", Safety: plugin.Destructive,
			Scope: "table",
			Inputs: []plugin.Field{
				{Name: "host", Type: plugin.String, Default: "localhost", Config: "host", Local: true},
				{Name: "table", Type: plugin.String, Help: "which table"},
			},
			Run: func(_ context.Context, req plugin.Request) (view.View, error) {
				if req.DryRun {
					previews.Add(1)
					return view.Text{Body: "would drop " + req.String("table") +
						" on " + req.String("host")}, nil
				}
				return view.Text{Body: "dropped"}, nil
			},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("RTA_DATA_DIR", dir)
	t.Setenv("RTA_CONFIG", dir+"/config.yaml")
	if err := writeFile(dir+"/config.yaml", twoProfiles); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := connectWith(t, reg, Options{
		AllowDestructive: []string{"pg.drop"},
		Origin:           reg.Origin,
		Profiles:         cfg,
		Reload:           func() config.Config { return cfg },
		Active:           func() string { return "" },
		Consent:          true,
		ConsentPreview:   true,
		ConsentWait:      600 * time.Millisecond,
	})
	seen := make(chan consent.Request, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if pending, err := consent.Pending(); err == nil && len(pending) > 0 {
				seen <- pending[0]
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	callTool(t, s, "pg_drop", map[string]any{"table": "invoices", "profile": "prod"})

	select {
	case req := <-seen:
		if req.Profile != "prod" {
			t.Fatalf("the request names %q", req.Profile)
		}
		if req.Preview != "" {
			t.Fatalf("a profiled call was previewed against the wrong place: %q", req.Preview)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing was parked, so this proves nothing")
	}
	if n := previews.Load(); n != 0 {
		t.Fatalf("the handler was dry-run %d times without the connection it would use", n)
	}
}

func TestAPacedGrantIsNotAConsentQuestion(t *testing.T) {
	// The budget and the prompt would otherwise cancel each other out: an
	// agent that could turn every throttled call into a question would spend
	// its way past a pace the operator set deliberately, by making them
	// answer the same prompt ten more times. That is the consent-fatigue
	// attack the queue cap already guards from the other side.
	s := connect(t, Options{
		AllowWrite:  []string{"demo"},
		Consent:     true,
		ConsentWait: 20 * time.Second,
	})
	// A grant that covers the call and allows one use an hour, already spent.
	if verr := grant.Issue(grant.Grant{
		Target: "demo.item.reveal", Scope: "db-password",
		Issued: time.Now(), Expires: time.Now().Add(time.Hour),
		RateMax: 1, RateWindow: "1h",
		Recent: []time.Time{time.Now().UTC().Truncate(time.Second)},
		Uses:   1,
	}, true); verr != nil {
		t.Fatal(verr)
	}

	start := time.Now()
	res := callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"})
	if !res.IsError {
		t.Fatal("a call went through a spent pace")
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("the call parked and waited %s instead of being told to come back", waited)
	}
	if pending, _ := consent.Pending(); len(pending) != 0 {
		t.Fatalf("a throttled call asked the operator: %+v", pending)
	}
	text := res.Content[0].(*sdk.TextContent).Text
	if !strings.Contains(text, "core.grant.rate") {
		t.Fatalf("the agent was not told this is a pace: %s", text)
	}
	if !strings.Contains(text, "try again in") {
		t.Fatalf("the refusal does not say when to come back, so a model retries: %s", text)
	}
}

func TestConsentIsNotAskedForWhatIsNotAPermissionQuestion(t *testing.T) {
	s := connect(t, Options{
		AllowWrite:  []string{"demo"},
		Consent:     true,
		ConsentWait: 20 * time.Second,
	})
	// A malformed argument is a statement about the call, not about
	// permission: asking a person to approve a call that is wrong on its
	// own terms teaches them to approve without reading.
	res := callTool(t, s, "demo_item_reveal", map[string]any{"key": 42})
	if !res.IsError {
		t.Fatal("a wrong-typed argument was accepted")
	}
	if pending, _ := consent.Pending(); len(pending) != 0 {
		t.Fatalf("a bad-argument refusal asked the operator: %+v", pending)
	}
}

func TestConsentNeverWidensTheSurface(t *testing.T) {
	// A capability the operator did not expose is not a tool, and no amount
	// of asking makes it one.
	s := connect(t, Options{Consent: true, ConsentWait: 20 * time.Second})
	tools := listTools(t, s)
	if _, ok := tools["demo_item_reveal"]; ok {
		t.Fatal("consent put a write capability on the read-only surface")
	}
	if _, ok := tools["demo_item_rm"]; ok {
		t.Fatal("consent put a destructive capability on the surface")
	}
	if pending, _ := consent.Pending(); len(pending) != 0 {
		t.Fatal("something was parked for a tool that does not exist")
	}
}

func TestWithConsentOffNothingIsEverParked(t *testing.T) {
	s := connect(t, Options{AllowWrite: []string{"demo"}})
	res := callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"})
	if !res.IsError {
		t.Fatal("the gate let a destructive call through")
	}
	if pending, _ := consent.Pending(); len(pending) != 0 {
		t.Fatalf("consent was off and a request was parked anyway: %+v", pending)
	}
}

func TestTheLedgerRecordsEveryCallIncludingRefusals(t *testing.T) {
	s := connect(t, Options{AllowWrite: []string{"demo"}})

	callTool(t, s, "demo_item_list", map[string]any{"name": "x"})   // read, open
	callTool(t, s, "demo_item_reveal", map[string]any{"key": "db"}) // refused: needs a grant
	callTool(t, s, "demo_item_fail", nil)                           // ran and failed
	callTool(t, s, "demo_item_list", map[string]any{"nosuch": "x"}) // refused: bad args

	entries, err := agentlog.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("the ledger holds %d entries, want one per call", len(entries))
	}
	if entries[0].Cap != "demo.item.list" || entries[0].Outcome != agentlog.Ran || entries[0].Auth != agentlog.Open {
		t.Fatalf("the read is misrecorded: %+v", entries[0])
	}
	if entries[1].Outcome != agentlog.Refused || entries[1].Code != "core.grant.required" {
		t.Fatalf("the refusal is misrecorded: %+v", entries[1])
	}
	if entries[2].Outcome != agentlog.Failed {
		t.Fatalf("a handler error should read as failed, not refused: %+v", entries[2])
	}
	if entries[3].Outcome != agentlog.Refused || entries[3].Code != "core.mcp.badargs" {
		t.Fatalf("the argument refusal is misrecorded: %+v", entries[3])
	}
	rep, err := agentlog.Verify()
	if err != nil || rep.Broken != 0 {
		t.Fatalf("the bridge wrote a broken chain: %v %+v", err, rep)
	}
}

func TestAHandlersOwnPolicyGateLedgersAsRefusedNotFailed(t *testing.T) {
	// The localOnly/humanOnly shape: the authority layer allows the call (an
	// open read), and the handler's own gate says no. That no used to be
	// sealed as Outcome=Failed — "the work broke" — which is exactly the row
	// an operator grepping outcome=refused during an incident would miss.
	s := connect(t, Options{})
	res := callTool(t, s, "demo_item_humanonly", nil)
	if !res.IsError {
		t.Fatal("the policy gate let the call through")
	}
	entries, err := agentlog.Read(0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("read: %v, %d entries", err, len(entries))
	}
	e := entries[0]
	if e.Outcome != agentlog.Refused {
		t.Fatalf("a refusal-marked error should read as refused, got %+v", e)
	}
	if e.Code != "demo.human" {
		t.Fatalf("the code should carry the gate's own, exactly: %+v", e)
	}
	// Auth deliberately keeps what the call earned. Blocked would say the
	// call never cleared the authority gate, and it did: open + refused is
	// the pair that tells a reader the handler's own policy said no.
	if e.Auth != agentlog.Open {
		t.Fatalf("the refusal should keep the authorization the call earned, got %+v", e)
	}
}

func TestTheLedgerNeverRecordsASecret(t *testing.T) {
	s := connect(t, Options{AllowWrite: []string{"demo"}})
	callTool(t, s, "demo_item_token", map[string]any{"token": "hunter2-in-the-log"})

	entries, err := agentlog.Read(0)
	if err != nil || len(entries) == 0 {
		t.Fatalf("read: %v %d", err, len(entries))
	}
	last := entries[len(entries)-1]
	if got, ok := last.Args["token"]; !ok || got != view.Mask {
		t.Fatalf("a Secret argument reached the ledger unmasked: %+v", last.Args)
	}
}

func TestTheLedgerRecordsWhatAStandingGrantAuthorized(t *testing.T) {
	s := connect(t, Options{AllowWrite: []string{"demo"}})
	allow(t, "demo.item.reveal", "")
	if res := callTool(t, s, "demo_item_reveal", map[string]any{"key": "db-password"}); res.IsError {
		t.Fatalf("granted call refused: %s", res.Content[0].(*sdk.TextContent).Text)
	}
	entries, _ := agentlog.Read(0)
	last := entries[len(entries)-1]
	if last.Auth != agentlog.Standing {
		t.Fatalf("auth = %q, want the standing grant recorded", last.Auth)
	}
}

// A parked call must not outlive the agent that made it: when the client
// gives up, the request goes with it rather than sitting there for somebody
// to answer into the void.
func TestACancelledCallStopsWaiting(t *testing.T) {
	s := connect(t, Options{
		AllowWrite:  []string{"demo"},
		Consent:     true,
		ConsentWait: 30 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.CallTool(ctx, &sdk.CallToolParams{
			Name: "demo_item_reveal", Arguments: map[string]any{"key": "db-password"},
		})
	}()
	// Let it park, then walk away.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if p, _ := consent.Pending(); len(p) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the parked call ignored its cancelled context")
	}
	// CallTool returning is the *client* giving up; the handler on the other
	// side is still unwinding. Ending the test there leaves its writes racing
	// t.TempDir's RemoveAll, which surfaces as "directory not empty" against
	// whichever test the cleanup happens to run under.
	//
	// The ledger entry is what to wait for, and picking it took two goes: the
	// request file leaving the queue looked like the end of the handler and
	// is not, because closing the request comes *before* recording the call.
	// Waiting on the earlier of the two put the race straight back. This is
	// also the assertion worth making — a call nobody answered is still a
	// call that happened, and it belongs in the record.
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := agentlog.Read(0)
		for _, e := range entries {
			if e.Cap == "demo.item.reveal" && e.Outcome == agentlog.Refused {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the cancelled call never reached the record")
}

// A tool called with `"arguments": null` — legal JSON, legal MCP, and what
// a client that sends the field explicitly produces — must not take the
// server down. Unmarshalling null into a map sets it to nil, and every
// write that follows panicked; on this surface that is one schema-valid
// call from an unprivileged agent ending the session for every other tool
// attached to it. The panic needed a capability with a declared default,
// which is why it survived until the ledger's tests called one with nil.
func TestNullArgumentsDoNotKillTheServer(t *testing.T) {
	s := connect(t, Options{})
	// demo.item.list declares a default (limit) and a required input
	// (name): the default is what made the old code write into the nil map
	// before anything could check the required one. The answer must be the
	// ordinary refusal, delivered by a server that is still running.
	res := callTool(t, s, "demo_item_list", nil)
	if !res.IsError || !strings.Contains(res.Content[0].(*sdk.TextContent).Text, "name is required") {
		t.Fatalf("unexpected answer to null arguments: %+v", res)
	}
	// The property that actually matters: the session survived.
	if res := callTool(t, s, "demo_item_list", map[string]any{"name": "x"}); res.IsError {
		t.Fatalf("the session did not survive: %s", res.Content[0].(*sdk.TextContent).Text)
	}
}

// watchPending reports whether anything was ever parked while it ran. It
// polls because the observation has to happen *during* a call: a parked
// request is removed when the call gives up, so looking afterwards always
// finds an empty directory whether or not the question was ever asked.
func watchPending(t *testing.T) (saw func() consent.Request, stop func()) {
	t.Helper()
	var mu sync.Mutex
	var found consent.Request
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if p, err := consent.Pending(); err == nil && len(p) > 0 {
				mu.Lock()
				found = p[0]
				mu.Unlock()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return func() consent.Request {
			mu.Lock()
			defer mu.Unlock()
			return found
		}, func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}
}

// Consent does not cross the `rta use` fence. While the operator
// works in one environment, agents are in that environment and nowhere else
// — the fence exists precisely so that decision is not re-opened
// per call, while distracted, which is the one posture in which people say
// yes to things. So a call naming another environment is refused without
// anybody being asked, and the same call naming the switched-on one is a
// question like any other.
func TestConsentDoesNotCrossTheSessionFence(t *testing.T) {
	f := newProfileFixture(t, twoProfiles, func(o *Options) {
		o.Consent = true
		o.ConsentWait = 3 * time.Second
	})
	if verr := profile.SaveSelection(profile.Selection{Active: "staging"}); verr != nil {
		t.Fatal(verr)
	}

	saw, stop := watchPending(t)
	started := time.Now()
	res := f.call(t, map[string]any{"profile": "prod", "sql": "select 1"})
	elapsed := time.Since(started)
	stop()
	if !res.IsError {
		t.Fatal("a call into an environment that is switched off went through")
	}
	if req := saw(); req.ID != "" {
		t.Fatalf("the operator was asked to approve a call across the fence: %+v", req)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the call parked for %s, so it was asked about after all", elapsed)
	}

	// …and the fence narrows rather than closes: the switched-on
	// environment is still a question somebody can answer.
	//
	// **One poller, not two, and that is a correctness fix rather than a
	// tidy-up.** This used to run watchPending alongside a separate goroutine
	// that answered whatever it found, with both polling consent.Pending()
	// every 5ms over the same single request. Whichever got there first
	// consumed it: when the answerer won, the watcher polled an empty queue
	// forever and the assertion below failed claiming the call had been
	// refused without asking — the exact opposite of what had happened, since
	// it had been asked *and answered*.
	//
	// Nothing about the code under test decides which goroutine wins, so it
	// passed on a quiet machine and failed on a loaded runner. Confirmed by
	// slowing the watcher's poll, which reproduces the CI failure verbatim.
	//
	// The goroutine that answers is the one that saw the request, so it is the
	// one that reports it, and there is no second reader to race.
	seen := make(chan consent.Request, 1)
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if p, err := consent.Pending(); err == nil && len(p) > 0 {
				seen <- p[0]
				_ = consent.Decide(p[0].ID, false, "test")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		// Closed rather than left open, so the receive below reports "nothing
		// was ever asked" instead of hanging until the test binary times out.
		close(seen)
	}()
	f.call(t, map[string]any{"profile": "staging", "sql": "select 1"})
	if req, ok := <-seen; !ok || req.ID == "" {
		t.Fatal("a call into the switched-on environment was refused without asking")
	}
}
