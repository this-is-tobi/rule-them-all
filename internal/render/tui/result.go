package tui

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/this-is-tobi/rta/internal/render/cli"
	"github.com/this-is-tobi/rta/internal/render/theme"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// The result pane: rendering what a run returned, the actions and view
// toggles a capability offers over it, and the footer that says so.

// resultMsg carries a finished capability run back into the update loop.
// Rendering happens at paint time so results adapt to the current width.
type resultMsg struct {
	cap     plugin.Capability
	view    view.View // for copy-as-JSON and re-rendering; nil on error
	elapsed time.Duration
	err     *view.Error
	// seq identifies the run this result belongs to. A result from a run the
	// user walked away from must not appear over whatever they walked to.
	seq int
}

// warningsBlock renders a page's degradations beneath its content, in the
// same heading-plus-rule grammar the sections themselves use.
//
// renderResult produces the viewport content for the current result at the
// current width; interactive lists get their selected row accented.
func (m *Model) renderResult() {
	var buf bytes.Buffer
	// Fill: this is a bordered pane of a fixed size, so a table narrower than
	// the frame is not restraint, it is a gap where a title could have been.
	opts := cli.Options{Format: cli.Pretty, Width: max(m.width-4, 20), Fill: true}
	if m.interactive() {
		opts.Highlight = m.row + 1
	}
	switch {
	case m.result.err != nil:
		_ = cli.RenderError(&buf, m.result.err, opts)
	case m.result.view != nil:
		if err := cli.Render(&buf, m.result.view, opts); err != nil {
			_ = cli.RenderError(&buf, view.AsError(err, "core.render.failed"), opts)
		}
	}
	content := strings.TrimRight(buf.String(), "\n")
	if meta := m.resultMeta(); meta != "" {
		content = meta + "\n\n" + content
	}
	m.viewport.SetContent(content)
	if m.interactive() {
		// Keep the selected row in view: meta(2) + table chrome(2) + row.
		line := m.row + 4
		top, h := m.viewport.YOffset(), m.viewport.Height()
		if line < top {
			m.viewport.SetYOffset(line)
		} else if line >= top+h-1 {
			m.viewport.SetYOffset(line - h + 2)
		}
	}
}

// resultMeta is the context line under the panel title: safety class in the
// shared status colors, idempotency, and the shape of what came back. It
// carries real information and keeps sparse results from floating in space.
func (m Model) resultMeta() string {
	if m.result.err != nil {
		return ""
	}
	sep := theme.Subtle.Render(" · ")
	parts := []string{theme.StatusStyle(string(m.current.Safety)).Render(string(m.current.Safety))}
	if m.current.Idempotent {
		parts = append(parts, theme.Subtle.Render("idempotent"))
	}
	switch v := m.result.view.(type) {
	case view.Table:
		n := len(v.Rows)
		total := max(v.Total, n)
		parts = append(parts, theme.Subtle.Render(fmt.Sprintf("%d of %d rows", n, total)))
		if m.interactive() && n > 0 {
			parts = append(parts, theme.Subtle.Render(fmt.Sprintf("row %d/%d", m.row+1, n)))
		}
	case view.KeyValue:
		parts = append(parts, theme.Subtle.Render(fmt.Sprintf("%d fields", len(v.Pairs))))
	case view.Chart:
		parts = append(parts, theme.Subtle.Render(fmt.Sprintf("%d series", len(v.Series))))
	case view.Text:
		if v.Markdown {
			parts = append(parts, theme.Subtle.Render("markdown"))
		}
	case view.Sections:
		titles := make([]string, 0, len(v.Items))
		for _, it := range v.Items {
			titles = append(titles, it.Title)
		}
		parts = append(parts, theme.Subtle.Render(strings.Join(titles, " › ")))
		// The title list is the page's table of contents, and a page that
		// lost three of its sections lists the survivors exactly as
		// confidently as a whole one does. This line is above the fold, so
		// it is where "you are not looking at all of it" has to be said.
		// Which parts and why is the renderer's job: the pane draws through
		// cli.Render, which already prints the warnings under the sections,
		// and a second copy here drew every one of them twice — in a
		// narrower block that truncated the messages the first copy wrapped.
		if n := len(pageWarnings(v)); n > 0 {
			parts = append(parts, theme.WarnText.Render(
				fmt.Sprintf("⚠ partial (%d %s)", n, pluralNoun(n, "warning"))))
		}
	}
	return " " + strings.Join(parts, sep)
}

// pluralNoun picks the noun form for n, and returns only the noun — the
// count is already in the caller's format string. Named apart from
// builtin/audit's plural, which returns "2 advisories" with the number
// folded in: two helpers, one name and two contracts is how "2 2 warnings"
// gets written by somebody reading the wrong one.
// The -y → -ies rule is carried because this package's most-counted noun is
// "capability", and the plugin inventory prints one per row for a plugin that
// declares exactly one — `debug` does. A naive "s" gave "1 capabilities" on a
// pane whose whole job is being read carefully.
func pluralNoun(n int, word string) string {
	if n == 1 {
		return word
	}
	if strings.HasSuffix(word, "y") && !strings.ContainsAny(word[len(word)-2:len(word)-1], "aeiou") {
		return word[:len(word)-1] + "ies"
	}
	return word + "s"
}

// pageWarnings collects what a composite page could not produce, recursing
// into nested pages: a detail view is sections of sections, so a sensor that
// failed two levels down is exactly as absent as one that failed at the top,
// and just as worth saying out loud.
func pageWarnings(v view.View) []view.Error {
	s, ok := v.(view.Sections)
	if !ok {
		return nil
	}
	out := append([]view.Error(nil), s.Warnings...)
	for _, item := range s.Items {
		out = append(out, pageWarnings(item.View)...)
	}
	return out
}

// flashText condenses an action result into a one-line footer notice.
func flashText(msg resultMsg) string {
	if t, ok := msg.view.(view.Text); ok {
		return t.Body
	}
	return msg.cap.ID + " done"
}

// toggleOn reports what a toggle is currently showing, which is not always
// what its field holds: runCmd turns `detail` on for a Detailed capability
// when nobody said otherwise, so an unset field is already on screen as on.
// Reading the raw map instead put an unticked box under a page that was
// plainly detailed, and spent the first press of D setting true on something
// that was already true — a keystroke whose entire effect was the tick mark
// appearing.
func (m Model) toggleOn(t viewToggle) bool {
	if on, given := m.lastValues[t.field].(bool); given {
		return on
	}
	return t.field == "detail" && m.current.Detailed
}

// toggleView re-runs the current view with one input flipped. The trail
// remembers the new values, so an action launched from here comes back to the
// list as the user left it rather than as it was first opened.
func (m Model) toggleView(t viewToggle) (tea.Model, tea.Cmd) {
	values := map[string]any{}
	for k, v := range m.lastValues {
		values[k] = v
	}
	values[t.field] = !m.toggleOn(t)
	m.lastValues = values
	if len(m.trail) > 0 {
		m.trail[len(m.trail)-1].values = values
	}
	m.row = 0
	return m, m.startRun(m.current, values, m.lastYes)
}

// selectedAction finds a tile action of the selected tile bound to key.
// "enter" specs are excluded: enter opens the tile itself.
func (m Model) selectedAction(key string) (capAction, bool) {
	if m.selected < 0 || m.selected >= len(m.tiles) || key == "enter" {
		return capAction{}, false
	}
	for _, a := range m.tiles[m.selected].actions {
		if a.key == key {
			return a, true
		}
	}
	return capAction{}, false
}

// runAction executes an action of the current view. The identity of the
// record it acts on comes from the selected row, from the record the page is
// already about, or from nowhere at all (add). Mutations reload the view
// afterwards; anything still missing — edit content, a destructive
// confirmation — opens a form first.
func (m Model) runAction(a capAction, tbl view.Table) (tea.Model, tea.Cmd) {
	base := map[string]any{}
	keys, _ := keyFields(a.cap)
	switch a.src {
	case srcRow:
		// A row names one record, so the first positional identifies it even
		// when the capability does not insist on one: `grant revoke` accepts
		// --all instead of a target, which does not make the target any less
		// the thing a row is about.
		if len(keys) == 0 {
			keys = firstPositional(a.cap)
		}
		if len(tbl.Rows) == 0 || len(keys) == 0 {
			return m, nil
		}
		row := tbl.Rows[min(m.row, len(tbl.Rows)-1)]
		if len(row) == 0 {
			return m, nil
		}
		// Every key input a column is named for, and the first column for
		// the first key otherwise. A record is not always one value: a lock
		// is a kind and a name, and a row that carries both should not open
		// a form asking for the half it is already showing.
		for i, f := range keys {
			raw, found := cellNamed(tbl, row, f.Name)
			if !found {
				if i != 0 {
					continue
				}
				raw = row[0]
			}
			v, err := rowKey(f, raw)
			if err != nil {
				return m, nil
			}
			base[f.Name] = v
		}
		// And every other input the row shows a column for: a grant row
		// carries its record, agent and profile, and `x` on one of two
		// note.rm rows used to revoke both because only the target seeded.
		// The boxes still open for anything a person would change; these
		// fill them with what the row already says.
		for _, f := range a.cap.Inputs {
			if _, done := base[f.Name]; done || f.Local || (f.Type != plugin.String && f.Type != plugin.Int) {
				continue
			}
			raw, found := cellNamed(tbl, row, f.Name)
			if !found {
				raw, found = cellNamed(tbl, row, columnAlias[f.Name])
			}
			if !found || strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "—" {
				continue
			}
			if v, err := rowKey(f, raw); err == nil {
				base[f.Name] = v
			}
		}
	case srcSelf:
		// The page already knows its subject: reuse the identity it ran with.
		for _, f := range keys {
			if v, ok := m.lastValues[f.Name]; ok {
				base[f.Name] = v
			}
		}
		if len(base) != len(keys) {
			return m, nil
		}
	}
	m.refreshPending = a.cap.Safety != plugin.Read
	// Removing the very record this page is about destroys the page: the
	// reload afterwards has to land one level further back.
	m.subjectGone = a.src == srcSelf && a.cap.Safety == plugin.Destructive
	// Read before m.current moves: an action carries on from the view it was
	// pressed in, so the form has to open on that view's inputs and not on
	// the declared defaults of the capability replacing it.
	prev := m.continuing(a.cap)
	// The environment travels with it, and it is not one of those inputs:
	// `profile` is reserved on a capability a profile can fill, so `asked`
	// filters it out by construction. Without this, a row from a listing run
	// against prod opened its removal form on whatever happened to be switched
	// on — the row identity from one connection, the call aimed at another —
	// and the non-form branch below erased the answer from lastValues as well,
	// re-aiming the next `r` too.
	if plugin.Profilable(a.cap) {
		if picked, ok := m.lastValues[profileInput]; ok {
			base[profileInput] = picked
		}
	}
	m.current = a.cap
	// A bare action waives only the optional-field form — never the
	// destructive confirmation, which is checked first on purpose.
	if a.cap.Safety == plugin.Destructive || (!a.bare && len(fieldsAfter(a.cap, base)) > 0) {
		return m.startFormWith(a.cap, base, prev)
	}
	m.lastValues, m.lastYes = base, false
	return m, m.startRun(a.cap, base, false)
}

// rowKey parses the selected row's identity cell to the key field's type.
// cellNamed returns the row's cell under the column whose header matches an
// input's name, case-insensitively — the convention that lets a producer
// mark which column is which identity without a second declaration.
// columnAlias maps an input to the column that shows it under another
// word: a grant's scope is its "Record" on screen, because that is what a
// person reads it as.
var columnAlias = map[string]string{"scope": "record"}

func cellNamed(tbl view.Table, row []string, name string) (string, bool) {
	if name == "" {
		return "", false
	}
	for i, c := range tbl.Columns {
		if i < len(row) && strings.EqualFold(c.Name, name) {
			return row[i], true
		}
	}
	return "", false
}

func rowKey(f plugin.Field, raw string) (any, error) {
	switch f.Type {
	case plugin.Int:
		return strconv.Atoi(strings.TrimSpace(raw))
	case plugin.Float:
		return strconv.ParseFloat(strings.TrimSpace(raw), 64)
	default:
		return raw, nil
	}
}

// resultFooterItems is the result pane's bar: only the keys that apply right
// now. Actionable views lead with their actions; row actions stay hidden until
// there is a row to act on.
//
// The conditions here mirror the switch in Update exactly, and that is the
// whole job. `e` used to be advertised only on a scrolled-past-the-top result
// while the key itself worked at any scroll position — so on the pane where an
// operator most wants to change an input and run it again, nothing said they
// could.
func (m Model) resultFooterItems() []hintItem {
	var keys []hintItem
	rerunnable := m.current.Run != nil && (m.result.view != nil || m.result.err != nil)
	if m.atTop() {
		if m.interactive() {
			keys = append(keys, labelled(bindColumn, "row"))
		}
		for _, a := range capActions(m.reg, m.current.ID) {
			if a.src == srcRow && !m.interactive() {
				continue
			}
			keys = append(keys, action(a.key, a.label))
		}
		for _, t := range viewToggleSpecs[m.current.ID] {
			// A toggle says which way it is pointing, or half the time it
			// reads as a thing you already did.
			label := t.label
			if m.toggleOn(t) {
				label = theme.GoodText.Render("✓") + " " + label
			}
			keys = append(keys, action(t.key, label))
		}
		if rerunnable {
			keys = append(keys, labelled(bindRerun, "refresh"))
		}
	} else {
		if rerunnable {
			keys = append(keys, item(bindRerun))
		}
		keys = append(keys, item(bindScroll))
	}
	// Outside the branch: `e` answers at any scroll position, and a pane that
	// only advertises it halfway down is advertising it where nobody is.
	if m.current.Run != nil && hasInputs(m.current) {
		keys = append(keys, item(bindEdit))
	}
	if m.result.view != nil {
		keys = append(keys, item(bindCopy))
	}
	if hint, ok := copyHint(m.current.ID, m.result.view); ok {
		keys = append(keys, hint)
	}
	return append(keys, item(bindBack), item(bindQuit))
}

// resultView frames the result in a titled panel: identity in the top
// border, cost on the right, contextual keys below.
func (m Model) resultView() string {
	head := capHead(m.current)
	if m.result.elapsed > 0 {
		head.Right = m.result.elapsed.Round(time.Millisecond).String()
	}

	footer := m.footerFor(modeResult)
	return panel(head, m.viewport.View(), m.width, m.height-lipgloss.Height(footer), false) + "\n" + footer
}

// capTitle renders a capability identity for a panel top border, with the
// same safety glyphs the browse list uses.
func capHead(c plugin.Capability) panelHead {
	id := c.ID
	switch c.Safety {
	case plugin.Write:
		id += " ✎"
	case plugin.Destructive:
		id += " ⚠"
	}
	return panelHead{Title: id, Note: c.Summary}
}
