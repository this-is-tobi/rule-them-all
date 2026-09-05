package tui

import (
	"github.com/this-is-tobi/rta/internal/registry"
	"github.com/this-is-tobi/rta/pkg/plugin"
)

// The one-key actions and view toggles a capability's result offers, and
// the tables that declare them per capability.

// actionSource says where an action gets the identity of the record it acts
// on — the one thing that differs between acting from a list and acting from
// the page of a single record.
type actionSource int

const (
	srcNone actionSource = iota // no subject: "add" needs nobody's id
	srcRow                      // the selected table row: the columns named for the keys, else its first column
	srcSelf                     // the record the current view is already about
)

// capAction opens a sibling capability from the view you are looking at: a
// button on a dashboard tile, a row action inside a result table, or an
// action on the detail page of one record.
type capAction struct {
	key   string
	label string
	cap   plugin.Capability
	src   actionSource
	// bare runs with what the source gave and asks for nothing more, where
	// the default is to open a form for any input still unfilled. It exists
	// because a declaration is not only for this screen: agent.deny carries
	// `server` and `passphrase` for answering a *remote* queue from the CLI,
	// and stopping the local one-key deny to ask about them would spend the
	// safe answer's whole property on inputs this screen never needs. A
	// required field is still safe under bare — the run refuses without it —
	// so what bare actually waives is the optional-field form, per action
	// and on purpose rather than by a global rule: kv.get's unlock form is
	// the counterexample that keeps this per-action (kv.list's own comment
	// tells that story).
	bare bool
}

// capActionSpecs declares which capabilities each view can reach in one key.
// One table drives every surface: dashboard tile buttons (minus "enter",
// which opens the tile), row actions inside result tables, and the actions
// on a record's own page — so a note is as editable as a task, wherever you
// happen to be looking at it. Keys must not collide with navigation
// (hjkl/arrows, tab, b, :, /, q), result keys (r, y, c), or "e" — "c" here
// means this table's own row-action copy (kv.list/kv.show → kv.copy); it is
// also the key copyvalue.go's copySpecs uses for a capability with no
// sibling action to copy through, checked both on a result already open
// (resultView) and directly against a tile's own preview (dashFooter,
// tui.go's modeDashboard "c" case). "e" is resultKeys' own generic "edit
// inputs" (dispatch.go) — reopen the form this result ran with, seeded —
// and resultKeys checks this table first, so an entry declaring "e" for
// itself would silently make edit-inputs unreachable for that capability
// rather than share the key: this table's own loop returns before the
// generic case is ever reached. A capability must not appear in both
// tables, or whichever one this loop or that case reaches first shadows
// the other's hint silently — today that would require a capability that
// both backs a tile (its own "overview") and declares a capActionSpecs "c"
// entry for itself, which none currently does.
var capActionSpecs = map[string][]struct {
	key, label, id string
	src            actionSource
	bare           bool
}{
	// One notebook, two kinds of thing in it, and `t` is the switch between
	// them: a note becomes a to-do with a checkbox, a to-do goes back to being
	// a note. Not bare — a one-key mutation is reserved for the fail-safe
	// direction — but its only input is the id the row supplies, so nothing is
	// left to ask and it runs on the keypress all the same.
	"note.list": {
		{"enter", "show", "note.show", srcRow, false},
		{"a", "add", "note.add", srcNone, false},
		{"u", "update", "note.edit", srcRow, false},
		{"t", "to-do/note", "note.toggle", srcRow, false},
		{"d", "done", "note.done", srcRow, false},
		// The undo for `d`, one key away from it: checking off the wrong
		// note is a one-keystroke mistake and should cost one keystroke to
		// take back.
		{"o", "re-open", "note.reopen", srcRow, false},
		{"x", "remove", "note.rm", srcRow, false},
	},
	// The hosts file is a list you manage, not just read: park an override
	// with `t`, drop it with `x`. `t` rather than `d` — d is "done" on the
	// task lists, and a key that means two things across two screens is a
	// key you hesitate over.
	"net.hosts.list": {
		{"a", "add", "net.hosts.add", srcNone, false},
		{"t", "toggle", "net.hosts.toggle", srcRow, false},
		{"x", "remove", "net.hosts.rm", srcRow, false},
	},
	// A finding names a package, and the question it raises second is what
	// pulled that package in — which decides whether the fix is a version bump
	// in a file you own or somebody else's release. `w` rather than a letter
	// already spoken for, and the same word every package manager uses for it.
	//
	// The form it opens is seeded with the path the listing ran against, so the
	// answer is about the project on screen rather than the working directory.
	"audit.deps": {
		{"w", "why", "audit.why", srcRow, false},
	},
	// The package table is where somebody decides to take an upgrade, so
	// taking it is one key from the row. Columns `target` and `package` are
	// named for pkg.upgrade's inputs, so both halves seed from the row and
	// the form only opens for the destructive confirmation.
	"pkg.outdated": {
		{"u", "upgrade", "pkg.upgrade", srcRow, false},
	},
	"pkg.tools": {
		{"u", "upgrade", "pkg.upgrade", srcRow, false},
	},
	// The managers table is where somebody learns which managers rta sees;
	// the next question is what one of them has behind, and the column is
	// named for pkg.outdated's input so the row answers it.
	"pkg.managers": {
		{"o", "outdated", "pkg.outdated", srcRow, false},
	},
	// A stale grant is something you notice on the dashboard, so taking it
	// back has to be possible from there and not only from a shell. `n`
	// renews the grant under the cursor — renew, not a fresh allow: the
	// re-issue path is the one `grant renew --help` warns turns a one-time
	// grant into an unlimited one.
	"grant.list": {
		{"a", "allow", "grant.allow", srcNone, false},
		{"n", "renew", "grant.renew", srcRow, false},
		{"x", "revoke", "grant.revoke", srcRow, false},
	},
	// The consent queue, answerable from the screen the operator is already
	// looking at: a parked call is a question with exactly two
	// answers, and until now both of them lived in another terminal.
	//
	// `a` and `d` are the verbs' own initials, and the asymmetry between them
	// is the point. Deny is bare, so it runs on the keypress — the safe
	// answer is one key, and a denial the operator did not mean costs the
	// agent a retry. Allow is not, so runAction opens its form (--ttl above
	// all): granting access stops for a confirmation, which is the direction
	// that cannot be taken back once a secret has been read. The asymmetry
	// used to fall out of the declarations alone — deny had no second input
	// — until the remote consent flow gave deny `--server` and a passphrase;
	// now it is declared here and pinned by consentpane_test.
	//
	// `d` also means "done" on the task lists, and net.hosts.list avoided
	// exactly that overlap. It is deliberate here: this screen is a security
	// prompt rather than another list, both keys spell their own verb, and
	// the mistake the overlap could produce — denying a call meant to be
	// allowed — is the recoverable one.
	"agent.pending": {
		// enter is "show" on every list in this table, and a parked call has
		// more to show than a row can hold — what it would actually do, most
		// of all. Reading before answering is the point, so the key that
		// opens the detail is the one already in everybody's fingers — and
		// bare, because a form between the list and the reading would teach
		// people to answer without the reading.
		{key: "enter", label: "show", id: "agent.show", src: srcRow, bare: true},
		{key: "a", label: "allow", id: "agent.allow", src: srcRow},
		{key: "d", label: "deny", id: "agent.deny", src: srcRow, bare: true},
		{key: "L", label: "lock", id: "lock.add", src: srcNone},
	},
	// And the two answers again from the detail page, so reading it does not
	// mean going back to the list to act on what you read.
	"agent.show": {
		{key: "a", label: "allow", id: "agent.allow", src: srcSelf},
		{key: "d", label: "deny", id: "agent.deny", src: srcSelf, bare: true},
		{key: "L", label: "lock", id: "lock.add", src: srcNone},
	},
	// The instant no, from the screens where you notice you need it. `L`
	// rather than `l` — l is navigation — and the form it opens is the whole
	// point: a lock names a kind and a principal, and neither is on the row
	// of a parked call in the spelling the gate verifies, so the operator
	// types both while looking at the call that made them want to. Lifting
	// one is a row action on the lock list itself, where both halves of the
	// principal are on the row and the surface matches them to lock.rm's
	// inputs by column name.
	"lock.list": {
		{"a", "lock", "lock.add", srcNone, false},
		{"x", "lift", "lock.rm", srcRow, false},
	},
	// The tile says how many calls are waiting; these are the two places to
	// go from there. `g` because l is navigation and every other letter in
	// "log" is spoken for. `w` is bare for the tile's own promise — "press w
	// to answer" has to land on the queue, not on a form asking which remote
	// server this machine's own waiting calls are on.
	"agent.overview": {
		{key: "w", label: "waiting", id: "agent.pending", src: srcNone, bare: true},
		{key: "g", label: "log", id: "agent.log", src: srcNone},
		{key: "L", label: "lock", id: "lock.add", src: srcNone},
	},
	// `v` reveals, and the argument for it is the argument that was originally
	// made against it, followed through.
	//
	// This table used to say: no reveal action, because "a secret shown
	// because a key was pressed on a list is a secret shown by accident" —
	// `kv get` asks for it by name, which is the point at which you meant to.
	// The reasoning is right and the conclusion did not follow, because it
	// measured the wrong thing. **The friction that makes a reveal deliberate
	// is not the typing; it is the unlock.** Every kv action opens the unlock
	// form on the way — the passphrase and identity are inputs like any other,
	// so `fieldsAfter` always has something left to ask — and an operator who
	// pressed `v` by accident is looking at a form naming the entry, not at
	// its value. The value then arrives on its own result page, titled with
	// the entry it belongs to, rather than in a cell of a list somebody was
	// scrolling.
	//
	// `c` was the tell. Copying is the same act with a smaller audience —
	// The catalogue classifies it identically for exactly that reason, "a value on
	// the clipboard has been revealed" — and it has been a row action here
	// since the beginning. The old comment argued the difference (no
	// scrollback, no screen share, undone by the next copy), and that
	// difference is real; what it does not support is making the *other* half
	// unreachable from the screen an operator is already on, which sent people
	// to a second terminal for a secret they had already unlocked the store
	// for.
	//
	// What stays refused is the thing actually worth refusing: nothing on this
	// screen puts a value in a row. `kv list` shows names, kinds and
	// descriptions, and the entry's page shows its metadata; a value appears
	// only where somebody asked for that one entry.
	//
	// kv.edit is still absent, for an unrelated reason: it hands the terminal
	// to $EDITOR, and the terminal is what this program is drawing on.
	"kv.list": {
		{"enter", "show", "kv.show", srcRow, false},
		{"v", "reveal", "kv.get", srcRow, false},
		{"c", "copy", "kv.copy", srcRow, false},
		{"a", "add", "kv.set", srcNone, false},
		{"s", "set", "kv.set", srcRow, false},
		{"m", "rename", "kv.rename", srcRow, false},
		{"x", "remove", "kv.rm", srcRow, false},
	},
	// The kv tile is `kv status`, which is about the store rather than any
	// entry — so its actions are the two things you want from there: the
	// list, and a new secret.
	"kv.status": {
		{"s", "secrets", "kv.list", srcNone, false},
		{"a", "add", "kv.set", srcNone, false},
	},
	"kv.show": {
		{"v", "reveal", "kv.get", srcSelf, false},
		{"c", "copy", "kv.copy", srcSelf, false},
		{"s", "set", "kv.set", srcSelf, false},
		{"m", "rename", "kv.rename", srcSelf, false},
		{"x", "remove", "kv.rm", srcSelf, false},
		{"a", "add", "kv.set", srcNone, false},
	},
	// The detail pages act on the record they are already showing.
	"note.show": {
		{"u", "update", "note.edit", srcSelf, false},
		{"t", "to-do/note", "note.toggle", srcSelf, false},
		{"d", "done", "note.done", srcSelf, false},
		{"o", "re-open", "note.reopen", srcSelf, false},
		{"x", "remove", "note.rm", srcSelf, false},
		{"a", "add", "note.add", srcNone, false},
	},
}

// viewToggle flips one boolean input of the view you are already looking at.
//
// It is not an action: nothing else runs and nowhere else opens. It is the
// filter on the list in front of you, which is a different thing and needs a
// different mechanism — `note.list` hides checked-off to-dos, so without this
// the re-open action could never find a row to act on. A capability that
// hides part of its own data by default owes the surface a way to ask for
// the rest.
type viewToggle struct {
	key, label, field string
}

var viewToggleSpecs = map[string][]viewToggle{
	"note.list": {{key: "A", label: "show done", field: "all"}},
	"kv.list":   {{key: "D", label: "detail", field: "detail"}},
}

// toggleFor resolves a key to a toggle declared for this capability.
func toggleFor(capID, key string) (viewToggle, bool) {
	for _, t := range viewToggleSpecs[capID] {
		if t.key == key {
			return t, true
		}
	}
	return viewToggle{}, false
}

// capActions resolves the declared actions for a capability against the
// registry. Unknown IDs simply do not appear.
func capActions(reg *registry.Registry, capID string) []capAction {
	var out []capAction
	for _, spec := range capActionSpecs[capID] {
		if c, ok := reg.Capability(spec.id); ok {
			out = append(out, capAction{key: spec.key, label: spec.label, cap: c, src: spec.src, bare: spec.bare})
		}
	}
	return out
}
