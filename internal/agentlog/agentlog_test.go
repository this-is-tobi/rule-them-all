package agentlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/this-is-tobi/rta/internal/seal"
)

// isolate points the data directory at a fresh temp dir, so a test never
// reads or writes the machine's real ledger.
//
// It also clears the missed counter, which is a package-level global and
// therefore outlives the temp directory by a long way. A test that makes an
// append fail on purpose leaves the count behind, and the *next* test to
// write a successful entry stamps that count onto it — so a burst of 300
// calls that were all recorded correctly reported twenty of them lost,
// because an unrelated test earlier in the shuffle had deliberately broken
// twenty appends. The counter working exactly as designed, and the isolation
// missing. Found by -shuffle, which is what it is for.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("RTA_DATA_DIR", dir)
	missed.Store(0)
	return dir
}

// keyForTest reads the ledger key the way the package does, for the tests
// that have to write a legitimate record of their own.
func keyForTest() ([]byte, error) { return seal.Key(keyFile, true) }

func write(t *testing.T, entries ...Entry) {
	t.Helper()
	for _, e := range entries {
		if err := Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
}

func TestTheLedgerChainsWhatItRecords(t *testing.T) {
	isolate(t)
	write(t,
		Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open},
		Entry{Cap: "kv.get", Args: map[string]any{"key": "db"}, Outcome: Refused, Auth: Blocked, Reason: "core.grant.required: no active grant"},
		Entry{Cap: "kv.get", Args: map[string]any{"key": "db"}, Outcome: Ran, Auth: Live},
	)
	got, err := Read(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d entries, wrote 3", len(got))
	}
	for i, e := range got {
		if e.Seq != int64(i+1) {
			t.Fatalf("entry %d has seq %d", i, e.Seq)
		}
		if e.Seal == "" {
			t.Fatalf("entry %d carries no seal", e.Seq)
		}
		if i > 0 && e.Prev != got[i-1].Seal {
			t.Fatalf("entry %d does not follow its predecessor", e.Seq)
		}
	}
	if got[0].Prev != "" {
		t.Fatal("the first entry claims a predecessor")
	}
	rep, err := Verify()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Broken != 0 {
		t.Fatalf("a freshly written chain reports broken at %d: %s", rep.Broken, rep.Why)
	}
	if rep.Entries != 3 {
		t.Fatalf("Verify counted %d entries", rep.Entries)
	}
}

func TestAnEditedLineIsVisible(t *testing.T) {
	isolate(t)
	write(t,
		Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open},
		Entry{Cap: "kv.get", Outcome: Refused, Auth: Blocked, Reason: "no grant"},
		Entry{Cap: "sys.mem", Outcome: Ran, Auth: Open},
	)
	// The tamper worth catching: rewriting a refusal into something
	// harmless, in place, keeping the seals.
	raw, err := os.ReadFile(Path())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var e Entry
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		t.Fatal(err)
	}
	e.Outcome, e.Reason = Ran, ""
	edited, _ := json.Marshal(e)
	lines[1] = string(edited)
	if err := os.WriteFile(Path(), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Broken != 2 {
		t.Fatalf("Verify reported broken=%d, want the edited entry 2 (%s)", rep.Broken, rep.Why)
	}
	if !strings.Contains(rep.Why, "seal") {
		t.Fatalf("why = %q, want it to name the seal", rep.Why)
	}
}

func TestARemovedLineIsVisible(t *testing.T) {
	isolate(t)
	write(t,
		Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open},
		Entry{Cap: "kv.get", Outcome: Refused, Auth: Blocked},
		Entry{Cap: "sys.mem", Outcome: Ran, Auth: Open},
	)
	raw, _ := os.ReadFile(Path())
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// Drop the middle entry entirely — the cover-up a plain per-line MAC
	// would not notice.
	kept := append([]string{lines[0]}, lines[2])
	if err := os.WriteFile(Path(), []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Broken == 0 {
		t.Fatal("a deleted entry left the chain looking whole")
	}
}

func TestAForgedEntryDoesNotVerify(t *testing.T) {
	isolate(t)
	write(t, Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open})
	last, err := Read(1)
	if err != nil || len(last) != 1 {
		t.Fatalf("read: %v", err)
	}
	// The write-only attacker: appends a flattering line
	// without being able to read the key.
	forged := Entry{
		Seq: 2, At: time.Now().UTC().Truncate(time.Second),
		Cap: "kv.get", Outcome: Ran, Auth: Open,
		Prev: last[0].Seal, Seal: strings.Repeat("ab", 32),
	}
	line, _ := json.Marshal(forged)
	f, err := os.OpenFile(Path(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(line, '\n'))
	f.Close()

	rep, err := Verify()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Broken != 2 {
		t.Fatalf("a forged entry verified (broken=%d)", rep.Broken)
	}
}

func TestAppendingContinuesAnExistingChain(t *testing.T) {
	isolate(t)
	write(t, Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open})
	// A second process appending later reads the tail rather than the whole
	// file, which is the path that has to keep the chain intact.
	write(t, Entry{Cap: "sys.mem", Outcome: Ran, Auth: Open})
	rep, err := Verify()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Broken != 0 || rep.Entries != 2 {
		t.Fatalf("chain broken at %d with %d entries", rep.Broken, rep.Entries)
	}
}

func TestVerifyRefusesALedgerWithNoKey(t *testing.T) {
	dir := isolate(t)
	write(t, Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open})
	// A ledger with no key beside it was not written by this rta — and
	// generating a fresh key to check it against would turn "unforgeable"
	// into "regenerate and accept".
	if err := os.Remove(filepath.Join(dir, keyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(); err == nil {
		t.Fatal("a keyless ledger verified")
	}
}

func TestReadLimitsToTheMostRecent(t *testing.T) {
	isolate(t)
	for i := 0; i < 10; i++ {
		write(t, Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open})
	}
	got, err := Read(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("Read(3) returned %d", len(got))
	}
	if got[2].Seq != 10 {
		t.Fatalf("Read(3) ended at seq %d, want the newest", got[2].Seq)
	}
}

func TestAnEnormousEntryIsTruncatedNotDropped(t *testing.T) {
	isolate(t)
	write(t, Entry{
		Cap:     "http.post",
		Args:    map[string]any{"body": strings.Repeat("x", maxLine*2)},
		Outcome: Ran, Auth: Open,
	})
	got, err := Read(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the call was dropped rather than recorded: %d entries", len(got))
	}
	if _, ok := got[0].Args["…"]; !ok {
		t.Fatalf("args were not summarised: %v", got[0].Args)
	}
	rep, err := Verify()
	if err != nil || rep.Broken != 0 {
		t.Fatalf("a truncated entry broke the chain: %v %+v", err, rep)
	}
}

func TestAMissingLedgerIsNotAnError(t *testing.T) {
	isolate(t)
	got, err := Read(10)
	if err != nil || len(got) != 0 {
		t.Fatalf("Read on a fresh machine: %v %d", err, len(got))
	}
	rep, err := Verify()
	if err != nil || rep.Entries != 0 || rep.Broken != 0 {
		t.Fatalf("Verify on a fresh machine: %v %+v", err, rep)
	}
}

// One oversized row used to end the record: a refusal that echoed a 3 MB
// argument wrote a 3 MB line, the tail reader found no line end in its
// window, and every append after it failed. Every string is bounded now,
// and a row written before that is read past rather than fatal.
func TestAnOversizedRowIsBoundedAndAnOldOneIsReadPast(t *testing.T) {
	isolate(t)
	huge := strings.Repeat("A", 3<<20)
	if err := Append(Entry{Cap: "fs.hash", Outcome: Failed, Auth: Open, Reason: huge, Args: map[string]any{"path": huge}}); err != nil {
		t.Fatal(err)
	}
	if err := Append(Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open}); err != nil {
		t.Fatalf("the append after an oversized one failed: %v", err)
	}
	got, err := Read(0)
	if err != nil || len(got) != 2 {
		t.Fatalf("read = %d entries, %v", len(got), err)
	}
	if len(got[0].Reason) > maxField+4 || got[0].Args["…"] == nil {
		t.Errorf("row was not bounded: reason %d bytes, args %v", len(got[0].Reason), got[0].Args)
	}
	rep, verr := Verify()
	if verr != nil || rep.Broken != 0 {
		t.Fatalf("a bounded record must verify: %+v %v", rep, verr)
	}

	// A record with a raw oversized line from before the bound: the next
	// append and every reader get past it.
	isolate(t)
	if err := Append(Entry{Cap: "sys.cpu", Outcome: Ran, Auth: Open}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(Path(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `{"seq":2,"at":"2026-08-28T00:00:00Z","capability":"fs.hash","outcome":"failed","auth":"open","reason":"%s","prev":"x","seal":"y"}`+"\n", strings.Repeat("B", 200<<10))
	f.Close()
	if err := Append(Entry{Cap: "sys.mem", Outcome: Ran, Auth: Open}); err != nil {
		t.Fatalf("append after a raw oversized line: %v", err)
	}
	if got, err := Read(0); err != nil || len(got) != 3 {
		t.Fatalf("read past the oversized line = %d, %v", len(got), err)
	}
	if _, verr := Verify(); verr != nil {
		t.Fatalf("verify must read past the oversized line: %v", verr)
	}
}
