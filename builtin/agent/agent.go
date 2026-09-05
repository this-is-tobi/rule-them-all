// Package agent is the operator's view of what AI agents are doing with
// rta: what they asked for and got (the ledger), what they are asking for
// right now (parked requests), and the answer.
//
// **None of it is reachable by an agent.** Every capability here refuses
// SurfaceMCP outright, reads included, and that is stronger than NeedsGrant
// on purpose. An agent that could approve its own parked request would make
// the mechanism theatre — the precedent grant.allow/grant.revoke already
// set — and one that could read the ledger could enumerate the operator's
// other agents, their profiles and their records, which is the inventory
// disclosure InputSchema already refuses to hand out. The right answer to
// both is not "with permission" but "not here".
//
// It is its own namespace rather than more of `grant` because the objects
// differ. A grant is a standing policy a person writes; a pending request
// is a question an agent asked; the ledger is history. `rta grant list`
// answers what may happen, `rta agent log` answers what did.
package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/this-is-tobi/rta/builtin/internal/timefmt"
	"github.com/this-is-tobi/rta/internal/agentlog"
	"github.com/this-is-tobi/rta/internal/consent"
	"github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/guard"
	operatorid "github.com/this-is-tobi/rta/internal/operator"
	"github.com/this-is-tobi/rta/internal/session"
	"github.com/this-is-tobi/rta/internal/stdio"
	"github.com/this-is-tobi/rta/pkg/format"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// maxRows bounds a listing. The ledger is append-only and unbounded; a
// table is a thing somebody reads.
const maxRows = 500

// Plugin returns the agent plugin declaration.
func Plugin() plugin.Plugin {
	return plugin.Plugin{
		Name:    "agent",
		Summary: "What AI agents asked rta for, what they got, and what is waiting on you",
		Capabilities: []plugin.Capability{
			{
				ID:      "agent.overview",
				Summary: "Agent activity at a glance: recent calls, refusals, anything waiting",
				Description: "The last hour of calls that arrived over MCP, how many were refused, " +
					"and how many requests are parked waiting for you to answer right now. With " +
					"--detail: the chain's integrity, where the ledger lives and how big it is.",
				Safety:     plugin.Read,
				Idempotent: true,
				Detailed:   true,
				Run:        localOnly(runOverview),
			},
			{
				ID:      "agent.log",
				Summary: "The record of what agents did — one line per call, refusals included",
				Description: "Every call that arrived over MCP: the capability, the arguments " +
					"(secrets masked), the profile, what happened, and how it was authorized — no " +
					"grant needed, a standing grant, or you answering live. The file is chained, so " +
					"an edited or missing line is visible: --detail verifies it and says where it " +
					"breaks. This is history and not policy; `rta grant list` is what may happen next.",
				Safety:     plugin.Read,
				Idempotent: true,
				Detailed:   true,
				NoPreview:  true, // agent.overview is the tile; this is the page
				Inputs: []plugin.Field{
					{Name: "limit", Type: plugin.Int, Default: 30, Min: 1, Max: maxRows,
						Help: "how many of the most recent calls to show"},
					{Name: "refused", Type: plugin.Bool, Help: "only the calls rta would not make"},
					{Name: "session", Type: plugin.String,
						Help: "only one server's calls — the id `rta agent overview` shows beside each connected client",
						Suggest: func(context.Context, plugin.Request) []string {
							open, _ := session.List()
							out := make([]string, 0, len(open))
							for _, s := range open {
								out = append(out, s.ID+"\t"+s.Agent+" "+s.Client)
							}
							return out
						}},
					{Name: "since", Type: plugin.String,
						Help: "only calls after this: a duration like `2h`, or a date like 2026-08-30"},
					{Name: "after", Type: plugin.Int, Min: 0,
						Help: "only calls after this `seq` — an exact cursor, for shipping the record somewhere"},
				},
				Run: localOnly(runLog),
			},
			{
				ID:      "agent.metrics",
				Summary: "The record as Prometheus metrics, for a dashboard and an alert",
				Description: "One command, the standard text exposition format, no listener and no " +
					"port: `rta agent metrics > /var/lib/node_exporter/textfile_collector/rta.prom` " +
					"on a timer is the whole integration. Calls by capability, agent, outcome and " +
					"how they were authorized; grants in force; calls parked waiting for you; and " +
					"whether the record's hash chain still verifies — which is the one worth an " +
					"alert, because a record that stops verifying is either a bug or somebody " +
					"editing it. Nothing is kept: every number is derived from the ledger, so it " +
					"is a number you could recompute. The Grafana stack's other half needs nothing " +
					"here — `agent log --after <seq> -o json` is already a cursor over an " +
					"append-only record, which is what a log shipper wants.",
				Safety:     plugin.Read,
				Idempotent: true,
				NoPreview:  true, // a full pass over the record is not a tile
				Run:        localOnly(runMetrics),
			},
			{
				ID:      "agent.pending",
				Summary: "Calls parked right now, waiting for you to allow or deny",
				Description: "With `rta mcp serve --consent`, a call that needs a grant nobody " +
					"issued is parked instead of refused, and waits for you. Each row is one such " +
					"call: its id, what it wants, against which connection, and how long it will " +
					"keep waiting. Answer with `rta agent allow <id>` or `rta agent deny <id>`. " +
					"With --server <name> (a server from remotes.yaml): the same queue read from a " +
					"remote rta server as a signed operator call, your operator key's passphrase " +
					"asked first.",
				Safety:     plugin.Read,
				Idempotent: true,
				Inputs: []plugin.Field{
					{Name: "server", Type: plugin.String, Local: true,
						Help: "read a remote server's parked queue instead of this machine's (a name from remotes.yaml)"},
					operatorid.PassphraseField,
				},
				Run: localOnly(runPending),
			},
			{
				ID:      "agent.show",
				Summary: "Everything about one parked call, including what it would do",
				Description: "The request in full: which capability, which record, against which " +
					"connection, every argument, and — for a destructive call rta could preview — " +
					"what running it would actually do, taken from the capability's own --dry-run. " +
					"That last part is the difference between approving an intention and approving " +
					"an outcome. Answer with `rta agent allow <id>` or `rta agent deny <id>`.",
				Safety:     plugin.Read,
				Idempotent: true,
				Inputs: []plugin.Field{
					{Name: "id", Type: plugin.String, Positional: true, Required: true,
						Help: "the request id from `rta agent pending`", Suggest: suggestPending},
					{Name: "server", Type: plugin.String, Local: true,
						Help: "the request is parked on this remote server (a name from remotes.yaml)"},
					operatorid.PassphraseField,
				},
				Run: localOnly(runShow),
			},
			{
				ID:      "agent.allow",
				Summary: "Allow one parked call",
				Description: "Authorizes exactly the call the request names, and nothing else — " +
					"the agent's call proceeds, and no standing state is created. With --ttl it " +
					"also issues the grant you would have typed (same target, same record, same " +
					"connection), which is worth doing when the same question is about to be asked " +
					"five more times. Never reachable over MCP: an agent that could answer its own " +
					"request would make the whole mechanism theatre. With --server <name>: answers " +
					"a call parked on a remote rta server as a signed operator call — every remote " +
					"answer costs your operator key's passphrase, one-shot included, because the " +
					"local one-shot's shell-equivalence argument does not travel a network.",
				Safety: plugin.Write,
				Scope:  "id",
				Inputs: []plugin.Field{
					{Name: "id", Type: plugin.String, Positional: true, Required: true,
						Help: "the request id from `rta agent pending`", Suggest: suggestPending},
					{Name: "ttl", Type: plugin.String,
						Help: "also issue a standing grant for this long, e.g. 15m (max 24h)"},
					// One passphrase field serves both gates that can ask: the
					// local guard's (with --ttl), and — with --server — the
					// operator key's. Same name, same channels, same argv refusal.
					guard.PassphraseField,
					{Name: "server", Type: plugin.String, Local: true,
						Help: "the request is parked on this remote server (a name from remotes.yaml)"},
				},
				Run: localOnly(runAllow),
			},
			{
				ID:      "agent.deny",
				Summary: "Deny one parked call",
				Description: "The agent's call is refused with your answer rather than with a " +
					"timeout, which is the difference between a model that stops and one that " +
					"retries. Never reachable over MCP. With --server <name>: denies a call parked " +
					"on a remote rta server, as a signed operator call.",
				Safety: plugin.Write,
				Scope:  "id",
				Inputs: []plugin.Field{
					{Name: "id", Type: plugin.String, Positional: true, Required: true,
						Help: "the request id from `rta agent pending`", Suggest: suggestPending},
					{Name: "server", Type: plugin.String, Local: true,
						Help: "the request is parked on this remote server (a name from remotes.yaml)"},
					operatorid.PassphraseField,
				},
				Run: localOnly(runDeny),
			},
			{
				ID:      "agent.reanchor",
				Summary: "Restore the mark that says where the record ends, when only the mark is lost",
				Description: "`rta agent log --detail` reports the record BROKEN for three different " +
					"reasons, and only one of them is repairable: the mark recording where the record " +
					"ends is gone or no longer verifies, while every entry on disk still checks out. " +
					"That is a lost note, not lost evidence, and until now it had no answer — deleting " +
					"the mark does not help, because absent is exactly the state being reported, so the " +
					"record stayed alarming forever.\n\nRefuses everything else, and that refusal is the " +
					"point: an entry whose seal fails means a line was edited, and a record shorter than " +
					"its mark means entries were removed from the end. Both are the chain doing its job, " +
					"and neither can be re-anchored away. Never reachable over MCP — an agent that could " +
					"clear the tamper signal on its own audit trail is the one thing this record exists " +
					"to prevent.",
				Safety: plugin.Destructive,
				Run:    localOnly(runReanchor),
			},
		},
	}
}

func runReanchor(_ context.Context, req plugin.Request) (view.View, error) {
	rep, err := agentlog.Verify()
	if err != nil {
		return nil, view.Errorf("agent.reanchor.unreadable", "the record could not be read: %v", err)
	}
	switch {
	case rep.Broken == 0:
		return nil, view.Errorf("agent.reanchor.whole",
			"the record is whole — there is nothing to re-anchor").
			WithHint("`rta agent log --detail` shows the record's state")
	case !rep.Unanchored:
		// Named rather than repaired, and the message says which of the two it
		// is: an operator who reads "cannot be repaired" without being told
		// what was found has no next step, and the next step here is to go and
		// look at the record rather than at rta.
		return nil, view.Errorf("agent.reanchor.evidence",
			"this is not a lost mark — entry %d %s", rep.Broken, rep.Why).
			WithHint("re-anchoring would erase that finding rather than fix it. The entries " +
				"themselves are what disagree, so the record is the thing to go and read")
	}
	if req.DryRun {
		return view.Text{Body: fmt.Sprintf(
			"would re-anchor the record at entry %d, its last entry — every one of the %d entries "+
				"on disk verifies, and only the mark recording where they stop is missing.",
			rep.Last, rep.Entries)}, nil
	}
	seq, err := agentlog.Reanchor()
	if errors.Is(err, agentlog.ErrNothingToRepair) {
		// Reachable only if the record changed between the check above and the
		// write, which means something appended and wrote its own mark — the
		// repair happened without this call.
		return nil, view.Errorf("agent.reanchor.whole",
			"the record was written to while this ran, and it now carries its own mark").
			WithHint("`rta agent log --detail` shows the record's state")
	}
	if err != nil {
		return nil, view.Errorf("agent.reanchor.failed", "re-anchoring the record: %v", err)
	}
	return view.Text{Body: fmt.Sprintf(
		"Re-anchored at entry %d. The record reads as whole again, and every entry it "+
			"carries is one that verified before the mark was written.", seq)}, nil
}

// localOnly refuses the MCP surface, in one place so that adding a
// capability here cannot forget it.
//
// The refusal names the reason rather than pretending the capability does
// not exist: a model that reads "not from here" stops, while one that reads
// "unknown tool" tries a different spelling.
func localOnly(h plugin.Handler) plugin.Handler {
	return func(ctx context.Context, req plugin.Request) (view.View, error) {
		if req.Surface() == plugin.SurfaceMCP {
			return nil, view.Refusef("agent.surface",
				"the agent namespace is for the person at the terminal, not for a caller over MCP").
				WithHint("consent and its record are about you deciding; ask the operator to run `rta agent pending`")
		}
		return h(ctx, req)
	}
}

func suggestPending(context.Context, plugin.Request) []string {
	reqs, err := consent.Pending()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.ID+"\t"+r.Cap+" "+strings.Join(r.Scopes, " "))
	}
	return out
}

// Connected is one short line naming every server a client has open right
// now — its --as name and how many calls it has made — and how many there
// are. Short on purpose: it sits on a dashboard tile forty cells wide, and
// a glance wants "claude is attached and has called twice", not a
// paragraph. What the client called itself, since when, and the session id
// are the detail page's table (connectedTable) and `rta agent log`'s column.
// Shared with `rta doctor`, so the two never describe presence in different
// words.
func Connected() (string, int) {
	open, calls := openSessions()
	if len(open) == 0 {
		return "", 0
	}
	parts := make([]string, 0, len(open))
	for _, s := range open {
		parts = append(parts, fmt.Sprintf("%s (%d %s)", agentOf(s), calls[s.ID], plural(calls[s.ID], "call", "calls")))
	}
	return fmt.Sprintf("%d — %s", len(open), strings.Join(parts, "; ")), len(open)
}

func openSessions() ([]session.Record, map[string]int) {
	open, err := session.List()
	if err != nil {
		return nil, nil
	}
	calls := map[string]int{}
	if len(open) > 0 {
		// Since the oldest open server started: every call of every open
		// session is inside that window, and nothing older matters here.
		// A second early: the record stamps entries to the second, and a
		// server's first call can land inside the second it started in.
		if entries, err := agentlog.Recent(open[0].Since.Add(-time.Second)); err == nil {
			for _, e := range entries {
				if e.Session != "" {
					calls[e.Session]++
				}
			}
		}
	}
	return open, calls
}

func agentOf(s session.Record) string {
	if s.Agent == "" {
		return "(unnamed)"
	}
	return s.Agent
}

// connectedTable is presence in full, one row per open server. The record
// column is the file that server writes to: when it is not the one this
// process reads, that is the whole explanation for an empty log.
func connectedTable() view.Table {
	open, calls := openSessions()
	t := view.Table{Columns: []view.Column{
		{Name: "agent"}, {Name: "client"}, {Name: "since", Kind: view.KindTimestamp},
		{Name: "calls"}, {Name: "session"}, {Name: "directory"}, {Name: "record"},
	}}
	for _, s := range open {
		t.Rows = append(t.Rows, []string{agentOf(s), s.Client, format.Ago(s.Since),
			strconv.Itoa(calls[s.ID]), s.ID, s.Dir, s.Ledger})
	}
	t.Total = len(t.Rows)
	return t
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func runOverview(_ context.Context, req plugin.Request) (view.View, error) {
	hour := time.Now().Add(-time.Hour)
	// Bounded by time, not by a display-sized window: a busy hour has more
	// than five hundred calls, and the tile said 500.
	entries, err := agentlog.Recent(hour)
	if err != nil {
		return nil, view.Errorf("agent.log.unreadable", "%v", err)
	}
	waiting, _ := consent.Pending()

	var recent, refused, approved int
	for _, e := range entries {
		recent++
		if e.Outcome == agentlog.Refused {
			refused++
		}
		if e.Auth == agentlog.Live {
			approved++
		}
	}
	// The one line on this tile that is about the present rather than the
	// past, and the only one that asks for anything. A bare count reads as
	// another statistic beside the other three; the number and the key to
	// press together are what turn a tile somebody glances at into a queue
	// somebody clears.
	nowWaiting := fmt.Sprintf("%d", len(waiting))
	if len(waiting) > 0 {
		nowWaiting += " — press w to answer"
	}
	// Presence before activity: "is anything attached" is the question
	// every zero below raises, and it is the one the ledger cannot answer.
	connected, n := Connected()
	if n == 0 {
		connected = "none — no client has an rta server open; `rta mcp install claude`, then restart the client"
	}
	pairs := []view.Pair{
		{Key: "waiting on you", Value: nowWaiting},
		{Key: "connected now", Value: connected},
		{Key: "calls in the last hour", Value: fmt.Sprintf("%d", recent)},
		{Key: "refused", Value: fmt.Sprintf("%d", refused)},
		{Key: "you approved live", Value: fmt.Sprintf("%d", approved)},
	}
	if last, err := agentlog.Read(1); err == nil && len(last) > 0 {
		pairs = append(pairs, view.Pair{Key: "last call",
			Value: fmt.Sprintf("%s %s, %s", last[0].Cap, last[0].Outcome, format.Ago(last[0].At))})
	} else {
		pairs = append(pairs, view.Pair{Key: "last call", Value: "nothing recorded yet"})
	}
	if !req.Bool("detail") {
		return view.KeyValue{Pairs: pairs}, nil
	}

	rep, verr := agentlog.Verify()
	return view.Sections{Items: []view.Section{
		{ID: "activity", Title: "Activity", View: view.KeyValue{Pairs: pairs}},
		{ID: "connected", Title: "Connected now", View: connectedTable()},
		{ID: "ledger", Title: "The record", View: view.KeyValue{Pairs: recordPairs(rep, verr)}},
		{ID: "waiting", Title: "Waiting on you", View: pendingTable(waiting)},
	}}, nil
}

// recordPairs describes the record itself: where it is, how much of it
// there is, how far back it goes, and whether it is intact.
//
// Retention is stated rather than left to be inferred. A reader who does
// not know that history was dropped will read "no calls before the 14th" as
// "nothing happened before the 14th", which is the one misreading a log
// must not invite.
func recordPairs(rep agentlog.Report, verr error) []view.Pair {
	pairs := []view.Pair{
		{Key: "file", Value: agentlog.Path()},
		{Key: "entries", Value: fmt.Sprintf("%d", rep.Entries)},
		{Key: "size", Value: format.Bytes(uint64(max(rep.Size, 0)))},
	}
	if rep.Files > 1 {
		pairs = append(pairs, view.Pair{Key: "files",
			Value: fmt.Sprintf("%d, rolled at 8 MB apiece", rep.Files)})
	}
	if rep.Missed > 0 {
		pairs = append(pairs, view.Pair{Key: "not recorded",
			Value: fmt.Sprintf("%d calls rta could not write down — the entries after them say where",
				rep.Missed)})
	}
	if rep.Retired > 0 {
		pairs = append(pairs, view.Pair{Key: "retired",
			Value: fmt.Sprintf("the first %d calls, dropped %s — the chain still verifies across the gap",
				rep.Retired, rep.RetiredAt.Local().Format("2006-01-02 15:04"))})
	}
	switch {
	case verr != nil:
		pairs = append(pairs, view.Pair{Key: "chain", Value: verr.Error()})
	case rep.Broken != 0:
		pairs = append(pairs, view.Pair{Key: "chain",
			Value: fmt.Sprintf("BROKEN at entry %d — %s", rep.Broken, rep.Why)})
	default:
		pairs = append(pairs, view.Pair{Key: "chain",
			Value: "whole — every entry follows the one before it, matches its seal, and the record ends where rta last left it"})
	}
	return pairs
}

func runLog(_ context.Context, req plugin.Request) (view.View, error) {
	limit := req.Int("limit")
	if limit <= 0 {
		limit = 30
	}
	onlyRefused := req.Bool("refused")
	after := int64(req.Int("after"))
	since, sinceErr := parseSince(req.String("since"))
	if sinceErr != nil {
		return nil, sinceErr
	}
	sess := strings.TrimSpace(req.String("session"))
	// Read more than asked for when filtering, so `--refused --limit 10`
	// answers with ten refusals rather than the refusals among the last ten
	// calls — which is the same number for a quiet server and nothing at
	// all for a busy one.
	//
	// --after and --since deliberately do not widen it, and the difference is
	// worth stating because the first draft widened all three. Those two keep
	// a *suffix* of a newest-first read: the newest thirty entries that pass
	// them are the newest thirty that pass them, whether thirty or five
	// hundred were read to find them. --refused keeps a scattered subset,
	// which is the only one of the three that can come up short.
	want := limit
	if onlyRefused || sess != "" {
		want = maxRows
	}
	var entries []agentlog.Entry
	var err error
	if after > 0 {
		// A cursor reads forward: the rows just past it, not the newest
		// rows that happen to be past it. The difference is the whole
		// shipping recipe — an archive appended from the newest end skips
		// whatever a burst wrote between two runs.
		entries, err = agentlog.ReadAfter(after, want)
	} else {
		entries, err = agentlog.Read(want)
	}
	if err != nil {
		return nil, view.Errorf("agent.log.unreadable", "%v", err)
	}
	filtered := onlyRefused || sess != "" || after > 0 || !since.IsZero()
	// Both columns appear only once a row can fill them, which for a record
	// written before agents were named — or before rta could serve over
	// HTTP at all — is never, and a column of em dashes on the screen an
	// operator opens in a hurry is a column they learn to skip.
	named, namedCred, coded, sessioned := false, false, false, false
	for _, e := range entries {
		if e.Agent != "" || e.Client != "" {
			named = true
		}
		// Same rule again: a record from before servers had ids shows no
		// session column, and one where they do shows which of several
		// same-named clients each call came from.
		if e.Session != "" {
			sessioned = true
		}
		if e.Credential != "" {
			namedCred = true
		}
		// Same appears-when-filled rule as the two above: a record written
		// before the code/reason split — or one where nothing has gone wrong
		// — shows no code column at all, rather than a column of blanks. Old
		// rows keep their glued "code: message" in why; new rows carry the
		// code here, exactly, which is the cell a shipped copy of this table
		// gets matched on.
		if e.Code != "" {
			coded = true
		}
	}
	// Filtered first, rendered second, because two of the rendering decisions
	// below are about the set rather than the row.
	shown := make([]agentlog.Entry, 0, limit)
	for i := len(entries) - 1; i >= 0 && len(shown) < limit; i-- {
		e := entries[i]
		switch {
		case onlyRefused && e.Outcome != agentlog.Refused:
		case sess != "" && e.Session != sess:
		case e.Seq <= after:
		case !since.IsZero() && e.At.Before(since):
		default:
			shown = append(shown, e)
		}
	}
	stamp := stampFormat(shown)
	rows := make([][]string, 0, len(shown))
	for _, e := range shown {
		row := []string{
			strconv.FormatInt(e.Seq, 10),
			e.At.Local().Format(stamp),
			e.Cap,
			argsLine(e.Args),
			e.Profile,
			string(e.Outcome),
			string(e.Auth),
			whyLine(e),
		}
		if coded {
			row = slices.Insert(row, len(row)-1, e.Code)
		}
		if named {
			row = slices.Insert(row, 3, whoCalled(e))
		}
		if namedCred {
			pos := 3
			if named {
				pos = 4
			}
			row = slices.Insert(row, pos, credentialCell(e))
		}
		if sessioned {
			row = slices.Insert(row, whoColumns(named, namedCred), sessionCell(e))
		}
		rows = append(rows, row)
	}
	// seq is first because it is the join key and the cursor: `--after` takes
	// it, and an archive without it cannot be appended to twice without
	// duplicating everything — which is what the documented way of shipping
	// this record actually did.
	cols := []view.Column{
		{Name: "seq"},
		{Name: "at", Kind: view.KindTimestamp}, {Name: "capability"}, {Name: "arguments"},
		{Name: "profile"}, {Name: "outcome", Kind: view.KindStatus},
		{Name: "authorized"}, {Name: "why"},
	}
	if coded {
		cols = slices.Insert(cols, len(cols)-1, view.Column{Name: "code"})
	}
	if named {
		cols = slices.Insert(cols, 3, view.Column{Name: "agent"})
	}
	if namedCred {
		pos := 3
		if named {
			pos = 4
		}
		cols = slices.Insert(cols, pos, view.Column{Name: "credential"})
	}
	if sessioned {
		cols = slices.Insert(cols, whoColumns(named, namedCred), view.Column{Name: "session"})
	}
	// Total is what the rows were chosen from; under a filter that is the
	// rows themselves — `0 of 500 rows` under --refused read as five
	// hundred refusals.
	total := len(entries)
	if filtered {
		total = len(shown)
	}
	table := view.Table{Columns: cols, Rows: rows, Total: total}
	if !req.Bool("detail") {
		return table, nil
	}
	rep, verr := agentlog.Verify()
	return view.Sections{Items: []view.Section{
		{ID: "calls", Title: "Calls", View: table},
		{ID: "integrity", Title: "The record itself", View: view.KeyValue{Pairs: recordPairs(rep, verr)}},
	}}, nil
}

func runPending(_ context.Context, req plugin.Request) (view.View, error) {
	if server := strings.TrimSpace(req.String("server")); server != "" {
		return remotePending(req, server)
	}
	reqs, err := consent.Pending()
	if err != nil {
		return nil, view.Errorf("agent.pending.unreadable", "%v", err)
	}
	return pendingTable(reqs), nil
}

func pendingTable(reqs []consent.Request) view.Table {
	// Shown only when something is asking under a name. The queue is the one
	// screen where the answer is a decision, so "which of my agents is this"
	// belongs beside the capability rather than one command away — and where
	// nobody has named an agent there is only ever one asker.
	asking := false
	for _, r := range reqs {
		if r.Agent != "" {
			asking = true
			break
		}
	}
	rows := make([][]string, 0, len(reqs))
	for _, r := range reqs {
		left := time.Until(r.Deadline).Truncate(time.Second)
		if left < 0 {
			left = 0
		}
		// The preview itself is prose and belongs on `agent show`; what the
		// list owes is the fact that there is one to read before answering.
		what := argsLine(r.Args)
		if r.Preview != "" {
			what = r.Preview
		}
		row := []string{
			r.ID, r.Cap, strings.Join(r.Scopes, " "), r.Safety, r.Profile,
			clip(what), left.String(),
		}
		if asking {
			row = slices.Insert(row, 1, r.Agent)
		}
		rows = append(rows, row)
	}
	cols := []view.Column{
		{Name: "id"}, {Name: "capability"}, {Name: "record"}, {Name: "safety", Kind: view.KindStatus},
		{Name: "profile"}, {Name: "would do"}, {Name: "expires in", Kind: view.KindDuration},
	}
	if asking {
		cols = slices.Insert(cols, 1, view.Column{Name: "agent"})
	}
	return view.Table{Columns: cols, Rows: rows, Total: len(rows)}
}

// whoCalled is the one cell that answers "which agent was this".
//
// **Two fields, and the rendering keeps them apart.** e.Agent is the operator's
// own name for this server and is what the grant was compared against; e.Client
// is what the caller announced for itself, which anything speaking the protocol
// can set to anything. So a name the operator chose is printed plainly, and a
// name only the client asserts is printed in parentheses — the parentheses mean
// "nobody checked this". Printing them the same way would be the more readable
// table and the dishonest one.
// whoColumns is where the session column goes: after whichever of the
// agent and credential columns are on screen, and before the arguments.
func whoColumns(named, namedCred bool) int {
	pos := 3
	if named {
		pos++
	}
	if namedCred {
		pos++
	}
	return pos
}

func sessionCell(e agentlog.Entry) string {
	if e.Session == "" {
		return "—"
	}
	return e.Session
}

func whoCalled(e agentlog.Entry) string {
	switch {
	case e.Agent != "":
		return e.Agent
	case e.Client != "":
		return "(" + e.Client + ")"
	default:
		return "—"
	}
}

// credentialCell is which bearer credential authenticated this call — a
// static token's label or an OIDC subject — distinct from whoCalled: --as
// names one principal per server, e.Client is whatever a caller claims about
// itself, and neither says which of possibly several valid tokens for that
// one server actually authenticated this particular row. Empty for every
// call served over stdio, where nothing on the wire verified an identity.
func credentialCell(e agentlog.Entry) string {
	if e.Credential == "" {
		return "—"
	}
	return e.Credential
}

func runShow(_ context.Context, req plugin.Request) (view.View, error) {
	id := strings.TrimSpace(req.String("id"))
	if server := strings.TrimSpace(req.String("server")); server != "" {
		return remoteShow(req, server, id)
	}
	r, ok := consent.Find(id)
	if !ok {
		return nil, unknownRequest(id)
	}
	return showView(r), nil
}

// showView renders one request in full, wherever it was fetched from — the
// local queue and a remote server's answer the same question, and two
// renderings would drift apart exactly where an operator compares them.
func showView(r consent.Request) view.View {
	left := time.Until(r.Deadline).Truncate(time.Second)
	if left < 0 {
		left = 0
	}
	pairs := []view.Pair{
		{Key: "capability", Value: r.Cap},
		{Key: "safety", Value: r.Safety},
	}
	if len(r.Scopes) > 0 {
		pairs = append(pairs, view.Pair{Key: "record", Value: strings.Join(r.Scopes, " ")})
	}
	if r.Profile != "" {
		pairs = append(pairs, view.Pair{Key: "connection", Value: r.Profile})
	}
	// Which agent asked, on the page where the operator decides. Omitted when
	// nothing was named, because "agent: —" on a detail page reads as a fact
	// about this request rather than as an absence of configuration.
	if r.Agent != "" {
		pairs = append(pairs, view.Pair{Key: "agent", Value: r.Agent})
	}
	pairs = append(pairs,
		view.Pair{Key: "why you are being asked", Value: r.Why},
		view.Pair{Key: "asked", Value: format.Ago(r.AskedAt)},
		view.Pair{Key: "expires in", Value: left.String()},
	)
	sections := []view.Section{
		{ID: "request", Title: "The request", View: view.KeyValue{Pairs: pairs}},
	}
	if len(r.Args) > 0 {
		arg := make([]view.Pair, 0, len(r.Args))
		keys := make([]string, 0, len(r.Args))
		for k := range r.Args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			arg = append(arg, view.Pair{Key: k, Value: fmt.Sprintf("%v", r.Args[k])})
		}
		sections = append(sections, view.Section{
			ID: "arguments", Title: "Arguments", View: view.KeyValue{Pairs: arg}})
	}
	// The preview, and the sentence that bounds it. An operator reading
	// "would remove task 4" has to know whether they are reading a fact
	// about this call or a guess — and for a capability rta will not
	// preview, silence would read as "it would do nothing".
	body := r.Preview
	if body == "" {
		body = notPreviewed(r)
	}
	sections = append(sections, view.Section{
		ID: "outcome", Title: "What it would do", View: view.Text{Body: body}})
	return view.Sections{Items: sections}
}

// notPreviewed says why there is no preview, in the caller's terms.
func notPreviewed(r consent.Request) string {
	switch {
	case r.Safety != string(plugin.Destructive):
		return "no preview: rta previews destructive calls, and this one is a " + r.Safety +
			" — the capability and its arguments above are the whole of it"
	case r.Profile != "":
		return "no preview: this call names a connection, and rta resolves connections only " +
			"after you answer — a preview run without one would describe the wrong place convincingly"
	default:
		return "no preview: either this capability comes from an external plugin, whose --dry-run " +
			"is a promise rta cannot check, or its preview did not finish in time"
	}
}

// answeredBy names the surface that answered, for the decision file and the
// ledger. It was the literal "cli" once, which the TUI inherited by
// dispatching this same capability — a label, not a lie, but a wrong one.
// answeredBy is measured, not asserted: the same origin a grant records,
// so a one-shot answer typed at a terminal reads as such and one issued by
// a process with no terminal — an agent with a shell answering its own
// question — reads as "command", the way a self-issued grant does.
func answeredBy(req plugin.Request) string {
	return grant.Origin(req.Surface(), term.IsTerminal(int(stdio.Real().Fd())))
}

func runAllow(_ context.Context, req plugin.Request) (view.View, error) {
	id := strings.TrimSpace(req.String("id"))
	if server := strings.TrimSpace(req.String("server")); server != "" {
		return remoteAnswer(req, server, id, true)
	}
	r, ok := consent.Find(id)
	if !ok {
		return nil, unknownRequest(id)
	}
	if req.DryRun {
		return view.Text{Body: fmt.Sprintf("would allow %s (%s) for the agent waiting on request %s",
			r.Cap, strings.Join(r.Scopes, " "), id)}, nil
	}
	// The team's ceiling binds a live "yes" exactly as it binds `grant allow`:
	// `never`/`neverProfile` are documented as needing nobody's agreement, not
	// as a default a rushed answer can override. Without this, a capability or
	// connection the policy forbids outright still reached internal/mcp's
	// askConsent — Reserve's refusal for "ceiling-suppressed" and "simply
	// ungranted" is deliberately the same core.grant.required, so an agent
	// cannot tell the two apart — and a bare `agent allow <id>` approved it
	// with no ceiling check anywhere in the path; only the --ttl branch below,
	// through alsoGrant, ever consulted the ceiling, and only after this
	// approval had already run. Checked here, at the one place a live
	// approval is minted, rather than duplicated where the call gets parked —
	// a second gate that could disagree with this one is the mistake
	// checkAgainst's own comment (internal/grant/grant.go) already names.
	scope := ""
	if len(r.Scopes) == 1 {
		scope = r.Scopes[0]
	}
	if verr := grant.CheckCeiling(r.Cap, scope, r.Profile); verr != nil {
		return nil, verr
	}
	// The guard, before the decision and not after: answering consumes the
	// parked request, so a passphrase refused past that point would release
	// the call, lose the standing grant, and leave nothing to retry against.
	// Refused here, the request stays parked and the retry costs a rerun.
	// The one-shot answer itself stays passphrase-free on purpose — it
	// releases a single call an agent with a shell could have run directly,
	// while --ttl mints authority that outlives this conversation, which is
	// exactly what the guard exists to price.
	var signer *guard.Signer
	if strings.TrimSpace(req.String("ttl")) != "" && guard.Enabled() {
		s, verr := guard.UnlockPrompted(req)
		if verr != nil {
			return nil, verr
		}
		signer = &s
	}
	if err := consent.Decide(id, true, answeredBy(req)); err != nil {
		return nil, view.Errorf("agent.allow.failed", "%v", err)
	}
	pairs := []view.Pair{
		{Key: "allowed", Value: strings.TrimSpace(r.Cap + " " + strings.Join(r.Scopes, " "))},
		{Key: "for", Value: "this call only"},
	}
	if ttl := strings.TrimSpace(req.String("ttl")); ttl != "" {
		// Measured here rather than inside alsoGrant because the surface is
		// this request's fact, not the parked call's.
		from := grant.Origin(req.Surface(), term.IsTerminal(int(stdio.Real().Fd())))
		note, verr := alsoGrant(r, ttl, from, signer)
		if verr != nil {
			// The call is already allowed; a bad --ttl must not read as if
			// nothing happened.
			pairs = append(pairs, view.Pair{Key: "grant", Value: "not issued: " + verr.Message})
			return view.KeyValue{Pairs: pairs}, nil
		}
		pairs[1] = view.Pair{Key: "for", Value: note}
	}
	return view.KeyValue{Pairs: pairs}, nil
}

// alsoGrant issues exactly the grant the operator would have typed.
//
// Through internal/grant's own path, so a grant issued from a prompt is
// indistinguishable from one issued deliberately — it appears in
// `rta grant list`, expires the same way, and is bound to the same
// connection. A second mechanism that also authorizes calls would be a
// second thing to audit.
func alsoGrant(r consent.Request, ttl, from string, signer *guard.Signer) (string, *view.Error) {
	asked, err := time.ParseDuration(ttl)
	if err != nil {
		return "", view.Errorf("agent.allow.ttl", "%q is not a duration", ttl).
			WithHint("try 15m, 1h — the maximum is 24h")
	}
	if asked <= 0 {
		return "", view.Errorf("agent.allow.ttl", "a grant has to last longer than nothing")
	}
	// The same two ceilings grant.allow's own parseTTL applies, by the same
	// call: rta's own day first, then whatever the team's policy file says.
	// Skipping this made the answer given below a lie by omission —
	// internal/grant.Load() re-applies the team's ceiling on every read
	// regardless of what issued the grant, so a standing grant from here
	// that outran a 15m policy stopped being honoured after 15m, with the
	// "for the next 4h" this function had just told the operator never
	// having said so.
	d, byPolicy, where := grant.ClampTTL(min(asked, grant.MaxTTL))
	scope := ""
	if len(r.Scopes) == 1 {
		scope = r.Scopes[0]
	}
	// More than one record in a single call is not something a standing
	// grant can express narrowly, and widening it to the whole capability
	// is not what the operator asked for by typing --ttl.
	if len(r.Scopes) > 1 {
		return "", view.Errorf("agent.allow.ttl",
			"this call names %d records, so there is no single grant that covers it and nothing else", len(r.Scopes))
	}
	now := time.Now()
	g := grant.Grant{
		Target: r.Cap,
		Scope:  scope,
		// The name and the connection behind it, exactly as `grant allow`
		// records them: the pin is what makes this a grant against a place
		// rather than against a label.
		Profile:    r.Profile,
		ProfilePin: r.Pin,
		// And who asked. Without it, answering a named agent's question with
		// --ttl would issue a grant covering the *unnamed* server — a grant
		// that reads as consent, lists as live, and never authorizes the
		// agent it was granted to.
		Agent:  r.Agent,
		Issued: now,
		// Measured, never assumed. This was FromForm unconditionally once, on
		// the argument that answering a parked request is always a person —
		// but `rta agent allow` runs from any shell, and an agent that parks
		// a call through its own MCP session can answer it the same way it
		// would run `grant allow`. The assumption made this the one issuing
		// path where a self-issued grant got recorded as the *most* trusted
		// origin, while grant.allow was carefully writing `command` for the
		// identical act. Same measurement as grant.allow's, same honesty
		// clause: a pty can still fake `terminal`, and detection of the
		// ordinary case is still the point.
		From:    from,
		Expires: now.Add(d),
		TTL:     ttl,
		Note:    "issued while answering request " + r.ID,
	}
	// Signed after the Grant is fully built, so the signature covers the
	// struct as issued; Issue's own backstop refuses if the guard is on and
	// no signer reached this far.
	if signer != nil {
		grant.SignWith(*signer, &g)
	}
	if verr := grant.Issue(g, true); verr != nil {
		return "", verr
	}
	note := fmt.Sprintf("this call, and %s for the next %s", r.Cap, d)
	if d < asked {
		// Which ceiling bit, the same distinction grant.allow's own message
		// makes: "capped" with no source sends the operator to change a flag
		// that was never the problem.
		if byPolicy {
			note += fmt.Sprintf("; capped at %s by your team's policy (you asked for %s) — %s", d, asked, where)
		} else {
			note += fmt.Sprintf("; capped at the %s maximum (you asked for %s)", grant.MaxTTL, asked)
		}
	}
	return note, nil
}

func runDeny(_ context.Context, req plugin.Request) (view.View, error) {
	id := strings.TrimSpace(req.String("id"))
	if server := strings.TrimSpace(req.String("server")); server != "" {
		return remoteAnswer(req, server, id, false)
	}
	r, ok := consent.Find(id)
	if !ok {
		return nil, unknownRequest(id)
	}
	if req.DryRun {
		return view.Text{Body: "would deny " + r.Cap + " for request " + id}, nil
	}
	if err := consent.Decide(id, false, answeredBy(req)); err != nil {
		return nil, view.Errorf("agent.deny.failed", "%v", err)
	}
	return view.KeyValue{Pairs: []view.Pair{
		{Key: "denied", Value: strings.TrimSpace(r.Cap + " " + strings.Join(r.Scopes, " "))},
		{Key: "the agent", Value: "gets your answer rather than a timeout"},
	}}, nil
}

// unknownRequest is the answer when an id names nothing answerable.
//
// Every capability here that takes an id funnels through it — show, allow and
// deny — so that the one case worth distinguishing is distinguished in one
// place. That case is a request that *is* on disk and does not describe the
// call it is bound to: something rewrote it after rta parked it, which is an
// attempt to have the operator approve one call while reading another. It is
// refused either way, and reporting it as "no request is waiting" would file
// an attack on the consent prompt under housekeeping — the operator would
// shrug at a stale id and never learn that something on their machine is
// writing into rta's data directory.
func unknownRequest(id string) *view.Error {
	q, err := consent.Scan()
	if err == nil {
		for _, bad := range q.Tampered {
			if bad != id {
				continue
			}
			return view.Errorf("agent.request.tampered",
				"request %q does not describe the call it is bound to, so it cannot be answered", id).
				WithHint("something rewrote it after rta parked it — the call it really names was " +
					"never released, and `rta doctor` reports this; whatever can write " +
					"rta's data directory is the thing to look at")
		}
	}
	e := view.Errorf("agent.request.unknown", "no request %q is waiting", id)
	if err != nil || len(q.Waiting) == 0 {
		return e.WithHint("nothing is waiting — a parked call expires on its own, and the agent is told")
	}
	ids := make([]string, 0, len(q.Waiting))
	for _, r := range q.Waiting {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return e.WithHint("waiting right now: " + strings.Join(ids, ", "))
}

// whyLine is the last column: the refusal or error, and — where there was
// one — the admission that calls just before this one went unrecorded.
//
// On the row rather than in a footnote, because the gap has a position: an
// operator reading down this column to find out what happened at 14:32 has
// to be able to see that something at 14:32 is missing.
func whyLine(e agentlog.Entry) string {
	if e.Missed == 0 {
		return e.Reason
	}
	note := fmt.Sprintf("(%d call before this one could not be recorded)", e.Missed)
	if e.Missed > 1 {
		note = fmt.Sprintf("(%d calls before this one could not be recorded)", e.Missed)
	}
	if e.Reason == "" {
		return note
	}
	return e.Reason + " " + note
}

// argsLine renders arguments for one table cell: compact, ordered, and
// never wider than a person will read.
func argsLine(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, args[k]))
	}
	return clip(strings.Join(parts, " "))
}

// clip bounds one table cell.
//
// Counted in runes, and cut on a rune boundary. A byte slice through text an
// agent chose ends in a replacement character whenever it is not ASCII — in
// the column a person reads while deciding whether to allow the call, which
// is the last place to put a mystery character.
func clip(line string) string {
	const wide = 60
	if utf8.RuneCountInString(line) <= wide {
		return line
	}
	cut := 0
	for i := range line {
		if cut == wide-1 {
			return line[:i] + "…"
		}
		cut++
	}
	return line
}

// parseSince reads what "since" means to a person: a duration back from now,
// or a day, or an exact instant.
//
// Three spellings because three questions ask it — "the last two hours" while
// something is going wrong, "today" when writing it up, and an exact
// timestamp when joining this record against another system's. Refused rather
// than guessed at when it is none of them: a filter that silently matched
// everything would report an empty record as a quiet one.
func parseSince(raw string) (time.Time, *view.Error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(raw); err == nil {
		if d < 0 {
			d = -d
		}
		return time.Now().Add(-d), nil
	}
	if t, ok := timefmt.ParseInstant(raw, time.Local); ok {
		return t, nil
	}
	return time.Time{}, view.Errorf("agent.log.since",
		"%q is not a time this understands", raw).
		WithHint("a duration back from now (`2h`, `15m`), a day (`2026-08-30`), " +
			"or an exact instant (`2026-08-30T14:00:00Z`)")
}

// stampFormat decides how much of an instant a row has to carry.
//
// The same table answers two questions. "What did it touch while I was in
// that meeting" is read on a terminal minutes later, where a date on every
// row is width taken from the arguments column; an archive is read months
// later, where a bare `15:04:05` is a row nobody can place. So the date
// appears exactly when it is load-bearing: when the rows are not all from
// today.
//
// The same shape as the agent column above it, which appears only once a row
// can fill it — a column that says nothing is a column people learn to skip.
func stampFormat(entries []agentlog.Entry) string {
	const timeOnly, dated = "15:04:05", "2006-01-02 15:04:05"
	today := time.Now().Local().Format("2006-01-02")
	for _, e := range entries {
		if e.At.Local().Format("2006-01-02") != today {
			return dated
		}
	}
	return timeOnly
}
