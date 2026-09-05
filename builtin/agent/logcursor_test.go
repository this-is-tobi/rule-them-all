package agent

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/this-is-tobi/rta/internal/agentlog"
	"github.com/this-is-tobi/rta/pkg/view"
)

// **A record you cannot append to twice is not an archive.**
//
// The documented way to keep this record — `rta agent log -o csv --limit
// 1000 >> archive.csv` on a timer — re-exported the same calls on every run.
// Measured before this existed: three calls, two runs, six rows and a second
// header line in the middle of the file. Nothing in the output could dedupe
// it either, because the sequence number the ledger already assigns was not
// in any column.
//
// So the cursor is the fix, and `seq` being visible is half of it.
func TestTheLogCanBeShippedWithoutDuplicatingWhatWasAlreadyShipped(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RTA_DATA_DIR", dir)
	for _, c := range []string{"sys.cpu", "sys.mem", "todo.list"} {
		if err := agentlog.Append(agentlog.Entry{Cap: c, Outcome: agentlog.Ran, Auth: agentlog.Open}); err != nil {
			t.Fatal(err)
		}
	}

	all := logRows(t, nil)
	if len(all) != 3 {
		t.Fatalf("%d rows, want 3", len(all))
	}
	// seq is the first column, because it is both the join key and what
	// --after takes.
	if all[0][0] == "" {
		t.Fatal("no sequence number on a row, so nothing can dedupe an archive")
	}

	// Ship everything, then ship again from the cursor: the second run has
	// nothing to say.
	high := all[0][0] // newest first
	again := logRows(t, map[string]any{"after": atoi(t, high)})
	if len(again) != 0 {
		t.Errorf("shipping from the cursor re-exported %d rows: %v", len(again), again)
	}

	// …and a cursor in the middle returns exactly what came after it.
	mid := logRows(t, map[string]any{"after": atoi(t, all[2][0])})
	if len(mid) != 2 {
		t.Errorf("from the oldest seq: %d rows, want the 2 after it", len(mid))
	}
}

// --since is the same question a person asks: what happened in the last hour.
func TestSinceReadsADurationADayAndAnInstant(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RTA_DATA_DIR", dir)
	if err := agentlog.Append(agentlog.Entry{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open}); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"1h", "24h", time.Now().Local().Format("2006-01-02")} {
		if rows := logRows(t, map[string]any{"since": spec}); len(rows) != 1 {
			t.Errorf("--since %q returned %d rows, want the one just written", spec, len(rows))
		}
	}
	if rows := logRows(t, map[string]any{"since": "1ns"}); len(rows) != 0 {
		t.Errorf("--since 1ns returned %d rows, want none", len(rows))
	}
}

// A filter that silently matched everything would report an empty record as a
// quiet one, which is the worst answer an audit trail can give.
func TestAnUnreadableSinceIsRefusedRatherThanIgnored(t *testing.T) {
	t.Setenv("RTA_DATA_DIR", t.TempDir())
	_, err := run(t, "agent.log", map[string]any{"since": "last tuesday"})
	if err == nil {
		t.Fatal("an unparseable --since was accepted")
	}
	verr, ok := err.(*view.Error)
	if !ok {
		t.Fatalf("want a view.Error, got %T", err)
	}
	if verr.Code != "agent.log.since" {
		t.Errorf("code = %s", verr.Code)
	}
	if !strings.Contains(verr.Hint, "2026-") && !strings.Contains(verr.Hint, "duration") {
		t.Errorf("the refusal does not say what would work: %s", verr.Hint)
	}
}

// A row read months later has to say which day it is from; a row read minutes
// later does not, and a date on every one of them is width taken from the
// arguments column. So the date appears exactly when it is load-bearing.
func TestTheDateAppearsOnlyWhenTheRowsAreNotAllFromToday(t *testing.T) {
	now := time.Now().Local()
	// Computed from today's own date rather than as "an hour ago", which is
	// yesterday for the hour after midnight — the first draft of this test
	// failed at 00:41 with the code behaving correctly.
	earlierToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 1, 0, time.Local)
	if got := stampFormat([]agentlog.Entry{{At: now}, {At: earlierToday}}); got != "15:04:05" {
		t.Errorf("all from today: format = %q, want the time alone", got)
	}
	old := []agentlog.Entry{{At: now}, {At: now.AddDate(0, 0, -2)}}
	if got := stampFormat(old); got != "2006-01-02 15:04:05" {
		t.Errorf("spanning days: format = %q, want the date too", got)
	}
}

// logRows runs agent.log with values and returns its rows.
func logRows(t *testing.T, values map[string]any) [][]string {
	t.Helper()
	v, err := run(t, "agent.log", values)
	if err != nil {
		t.Fatal(err)
	}
	tbl, ok := v.(view.Table)
	if !ok {
		t.Fatalf("want a Table, got %s", view.TypeOf(v))
	}
	return tbl.Rows
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("seq %q is not a number: %v", s, err)
	}
	return n
}

// A cursor reads forward. The shipping recipe appends whatever is past the
// archive's highest seq, and a burst between two runs used to lose its
// oldest rows: --after selected the newest rows past the cursor.
func TestAfterReadsForwardNotFromTheNewestEnd(t *testing.T) {
	isolate(t)
	for i := 0; i < 12; i++ {
		if err := agentlog.Append(agentlog.Entry{Cap: "sys.cpu", Outcome: agentlog.Ran, Auth: agentlog.Open}); err != nil {
			t.Fatal(err)
		}
	}
	rows := logRows(t, map[string]any{"after": 2, "limit": 5})
	got := map[string]bool{}
	for _, r := range rows {
		got[r[0]] = true
	}
	if len(rows) != 5 || !got["3"] || !got["7"] || got["8"] {
		t.Fatalf("--after 2 --limit 5 = %v, want seq 3..7", rows)
	}
}
