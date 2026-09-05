// Package tui is the interactive shell over the capability registry: one app
// that hosts every plugin's views. Capabilities never own the screen — the
// shell browses the registry, runs capabilities, and renders their Views.
//
// v0 scope: filterable capability browser (the proto command palette),
// direct execution of capabilities without required inputs, results in a
// scrollable pane with re-run and copy-as-JSON. Forms for required inputs
// (huh) and the dashboard land in the next M1 iteration.
package tui

import (
	"context"
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"

	"github.com/this-is-tobi/rta/internal/config"
	"github.com/this-is-tobi/rta/internal/pluginhost"
	"github.com/this-is-tobi/rta/internal/profile"
	"github.com/this-is-tobi/rta/internal/registry"
	"github.com/this-is-tobi/rta/internal/render/theme"
	"github.com/this-is-tobi/rta/internal/stdio"
	"github.com/this-is-tobi/rta/internal/textclean"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// bindTimeout bounds resolving what an environment contributes, which since
// `kube:` secrets can mean a cluster read rather than only a local store.
//
// Shorter than runTimeout because nobody asked for it: this runs while
// painting a switch, and an environment that cannot be resolved should leave
// the operator at a dashboard reporting so rather than at one that never
// finishes switching. Failures here are already dropped — the tile that needs
// the credential reports it — so the deadline only bounds how long that takes.
const bindTimeout = 10 * time.Second

type mode int

const (
	modeDashboard mode = iota
	modeBrowse
	modeForm
	modeRunning
	modeResult
	modePlugins
	modeProfiles
	modeProfilePlugins
	modeTheme
	modeCopyPick
)

// capItem adapts a capability to the bubbles list.
type capItem struct{ c plugin.Capability }

func (i capItem) FilterValue() string { return i.c.ID + " " + i.c.Summary }

// runRef remembers one actionable view — a list, or the page of a single
// record — so actions launched from it can hop out (show/edit/done/remove)
// and land back on it, refreshed.
type runRef struct {
	cap    plugin.Capability
	values map[string]any
}

// Model is the TUI shell.
type Model struct {
	reg *registry.Registry
	// pluginCfg answers what the operator stated for a namespace, already
	// matched to the artifact by internal/pluginconf. nil means nothing is
	// configured, which is the ordinary state.
	pluginCfg func(namespace string) map[string]any
	list      list.Model
	// cols carries the catalogue column widths, measured once so the
	// header above the list and the rows inside it agree.
	cols       capDelegate
	viewport   viewport.Model
	spinner    spinner.Model
	form       *capForm
	themeForm  *themeForm
	copyPick   *copyPickForm
	tiles      []tile
	dash       config.Dashboard // the arrangement, edited in place and saved
	selected   int              // selected dashboard tile
	scroll     int              // first visible dashboard tile row
	origin     mode             // where the current result/form was opened from
	mode       mode
	current    plugin.Capability // capability being viewed/run
	lastValues map[string]any    // inputs of the last run, reused by re-run
	lastYes    bool
	result     resultMsg
	flash      string // one-shot footer notice (e.g. "copied"), cleared on next key
	// armedDelete is the two-press gate on the profile panes' `d`: the first
	// press names what would be removed, the next `y` removes it, and any
	// other key disarms. It exists because `d` sat one mispress from the
	// navigation keys and deleted a whole environment — config entry, active
	// switch and every grant naming it — with less ceremony than the TUI
	// gives a Destructive capability's form, which stops for an explicit
	// confirmation stage. Holds the profile name in modeProfiles and the
	// plugin key in modeProfilePlugins; "" when nothing is armed.
	armedDelete string
	width       int
	height      int

	// Live search bar state (dashboard tile 0).
	searchEditing bool
	query         string
	searchSel     int
	searchInfo    string // idle prompt: plugin/capability inventory

	// Profiles panes: the operator's environments, which one is switched on,
	// and — one level in — the plugins each one covers.
	profiles      []profileRow
	profileSel    int
	profileScroll int
	// profileOpen is the environment whose plugin list is showing, empty on the
	// outer pane. Kept as the name rather than an index because the rows are
	// rebuilt from disk after every edit, and an index would survive a rename
	// pointing at whatever sorted into that slot.
	profileOpen string
	connSel     int
	connScroll  int

	// active is the environment switched on, refreshed with the tiles rather
	// than read at paint time. The dashboard has to show it — "am I in
	// production" is the question a header answers — and paint runs on every
	// keystroke, which is no place for a file read.
	active      string
	activeUntil *time.Time
	// activeColor is that environment's own colour, or "" for one nobody
	// marked. Cached beside the name and for the same reason: paint runs on
	// every keystroke and must not read a file.
	activeColor string
	// bound is the active environment's contribution to each capability, keyed
	// by capability ID.
	//
	// Resolved when the environment changes rather than per refresh, because
	// resolving it can mean unlocking the encrypted store: age's scrypt work
	// factor is about a second, and the dashboard refreshes every five. A
	// credential decrypted once and held for as long as the environment stands
	// is the same exposure the process already has while a capability runs, and
	// the alternative is a dashboard that spends a fifth of its life deriving a
	// key it already derived.
	bound map[string]envBind
	// boundStamp is what bound was resolved from — see environmentStamp. It is
	// the cache key, and it describes the environment rather than naming it,
	// because a profile edited in place keeps its name and changes its meaning.
	boundStamp string

	// Plugins pane: the inventory, and where a hidden tile comes back from.
	plugins []pluginRow
	// untrusted is what discovery found on $PATH and refused to launch. Held
	// on the Model rather than read from a package variable so two TUIs in one
	// test do not share it.
	untrusted []pluginhost.Untrusted
	pluginSel int
	// pluginScroll is the first plugin drawn. The pane used to clip instead
	// of scroll, so at 80x24 the last plugin was invisible while `j` still
	// selected it.
	pluginScroll int

	// In-flight run: its cancel func and the sequence number that tells its
	// result apart from one the user has already walked away from.
	cancelRun context.CancelFunc
	runSeq    int

	// tickGen names the current dashboard refresh chain. Every return to the
	// dashboard restarts refreshing (a tile can be stale after any amount of
	// time away) — which, without a generation to check, meant every return
	// left its predecessor's tea.Tick armed and about to re-arm itself
	// forever: nothing about `tickMsg{}` said which visit it belonged to, so
	// a stale chain looked exactly as valid as the current one. Ten trips
	// through browse and back left ten timers alive, each firing every tile
	// on every tick. Bumped by every call that (re)starts refreshing;
	// checked by the tick handler, which drops anything but the newest.
	tickGen int

	// Actionable-view state. trail is the chain of views the user walked
	// into (note.list → note.show); actions run against its last entry and
	// esc pops back up it.
	trail          []runRef
	row            int  // selected table row of the current list
	goalCol        int  // dashboard column vertical movement aims for
	refreshPending bool // a mutating action ran: reload the view it came from
	subjectGone    bool // …and that action destroyed that view's subject
}

// New builds the shell over a registry. dash configures the dashboard; its
// zero value is the automatic one-tile-per-plugin arrangement.
// New builds the shell. pluginCfg answers what the operator stated for a
// namespace, already matched to the artifact by internal/pluginconf; nil is a
// decision the caller has to type, which is the point.
//
// A parameter rather than a setter, for the same reason as
// plugin.Resolve's third argument: Run used to take this and New could not,
// so the value had nowhere to go and was dropped on the floor. Every surface
// that reads it — the form seed, the run, the dashboard refresh — then saw
// nil, and the operator's configuration reached the CLI and no part of the
// TUI. A constructor that can still be called the old way is the same defect
// waiting to be reintroduced.
// Option adjusts a Model at construction. Variadic so that the many call
// sites which need none of them say nothing.
type Option func(*Model)

// WithUntrusted supplies the plugin artifacts discovery found on $PATH and
// refused to launch, so the inventory can show them instead of leaving a
// person to wonder where a plugin they installed went.
func WithUntrusted(us []pluginhost.Untrusted) Option {
	return func(m *Model) { m.untrusted = us }
}

func New(reg *registry.Registry, dash config.Dashboard,
	pluginCfg func(namespace string) map[string]any, opts ...Option) Model {
	items := catalogueItems(reg)
	cols := newCapDelegate(items)
	l := list.New(items, cols, 0, 0)
	// Strip the list's own chrome: its help line speaks a different
	// vocabulary from the rest of the app ("↑/k up", "/ filter"), and its
	// title and status bar put four lines between the column header and the
	// first row. browseView draws all three in the app's own terms.
	// Filtering is untouched — the filter input renders on its own row
	// whether or not the title does (bubbles list.titleView).
	l.SetShowHelp(false)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)
	l.SetStatusBarItemName("capability", "capabilities")
	// The first item is a section header, and the cursor must not start on a
	// label: enter would do nothing and the list would look broken.
	for i, item := range l.Items() {
		if _, isHeader := item.(pluginHeader); !isHeader {
			l.Select(i)
			break
		}
	}

	sp := spinner.New(
		spinner.WithSpinner(spinner.MiniDot),
		spinner.WithStyle(lipgloss.NewStyle().Foreground(theme.Primary)),
	)
	m := Model{
		reg:       reg,
		pluginCfg: pluginCfg,
		list:      l,
		cols:      cols,
		viewport:  viewport.New(),
		spinner:   sp,
		tiles:     buildTiles(reg, dash),
		dash:      dash,
		mode:      modeDashboard,
		searchInfo: fmt.Sprintf("%d plugins · %d capabilities — press / to search",
			len(reg.Plugins()), len(reg.Capabilities())),
	}
	for _, opt := range opts {
		opt(&m)
	}
	// The name, before the first paint, so the header says where this session is
	// from the frame it opens on. The *binding* is Init's job, off the update
	// loop: resolving a `secrets:` reference is a key derivation, and a shell
	// that takes a second to appear is a shell people stop opening.
	m.active = profile.Active()
	m.activeColor = profileColor(m.active)
	m.boundStamp = environmentStamp(m.active)
	return m
}

// wheelStep is how many rows one notch of the wheel moves. Three is what
// every terminal pager uses, and a list that moves one row per notch reads
// as a list that is resisting.
const wheelStep = 3

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{refreshTiles(m.tiles, m.tickGen, m.pluginCfg, m.profileFor)}
	if m.active != "" {
		cmds = append(cmds, bindCmd(m.reg, m.active, m.boundStamp))
	}
	return tea.Batch(cmds...)
}

// isTop reports whether c is the actionable view the trail points at.
func (m Model) isTop(c plugin.Capability) bool {
	return len(m.trail) > 0 && m.trail[len(m.trail)-1].cap.ID == c.ID
}

// atTop reports whether the result on screen is the actionable view the
// trail currently points at — as opposed to a leaf result opened from it.
func (m Model) atTop() bool { return m.isTop(m.current) }

// interactive reports whether the current result is a row-navigable list.
// An actionable view with no rows is still actionable (you can add to an
// empty list) — it just has no row to select.
func (m Model) interactive() bool {
	if !m.atTop() {
		return false
	}
	tbl, ok := m.result.view.(view.Table)
	return ok && len(tbl.Rows) > 0
}

// enterTrail records the result on screen when it is a view you can act
// from: refreshing the current level, returning to an earlier one, or
// descending into a new one (a list into one record's page).
func (m *Model) enterTrail(c plugin.Capability, values map[string]any) {
	if len(capActions(m.reg, c.ID)) == 0 {
		return // a leaf result: esc simply returns to where it came from
	}
	for i := range m.trail {
		if m.trail[i].cap.ID == c.ID {
			m.trail = m.trail[:i+1]
			m.trail[i].values = values
			return
		}
	}
	m.trail = append(m.trail, runRef{cap: c, values: values})
}

// reopenTop re-runs the actionable view the trail points at, so it reflects
// whatever the action that just ran changed.
func (m Model) reopenTop() (tea.Model, tea.Cmd) {
	t := m.trail[len(m.trail)-1]
	m.current = t.cap
	m.lastValues, m.lastYes = t.values, false
	return m, m.startRun(t.cap, t.values, false)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		// The catalogue draws its own column header above the list and the
		// shared hint bar below it, so the list gets what is left rather
		// than the whole window — otherwise its last rows land under the
		// footer and the scroll position lies about what is reachable.
		m.list.SetSize(msg.Width, max(msg.Height-1-lipgloss.Height(m.browseFooter()), 3))
		m.viewport.SetWidth(msg.Width - 4)   // result panel: borders + padding
		m.viewport.SetHeight(msg.Height - 3) // panel top/bottom + footer
		m.clampScroll()                      // dashboard rows per screen changed
		if m.mode == modeResult {
			m.renderResult() // reflow to the new width
		}
		// A form open across a resize has to be re-fitted too, or it keeps the
		// height of a window that no longer exists.
		m.fitForm()
		m.fitThemeForm()
		m.fitCopyPick()
		return m, nil

	case tea.MouseWheelMsg:
		return m.wheel(msg)
	case spinner.TickMsg:
		if m.mode == modeRunning {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case completeMsg:
		return m.applyCompletion(msg)

	case tileMsg:
		if idx := m.tileIndexFor(msg); idx >= 0 {
			// Cleaned on arrival, for the same reason resultMsg is: what the
			// model stores and what the screen shows must be one string.
			//
			// Nothing today reads a tile's view except cli.Render, which
			// sanitises its own local copy — so this was already safe, and
			// safe only because no second reader exists. That is exactly the
			// arrangement that produced the runAction bug, where the cell on
			// screen came from the sanitised copy and the row's identity came
			// from the raw one. A tile is a view with a dashboard action
			// attached; the second reader is a matter of time.
			m.tiles[idx].view = view.MapStrings(msg.v, textclean.Terminal)
			m.tiles[idx].err = view.MapErrorStrings(msg.err, textclean.Terminal)
		}
		return m, nil

	case tea.MouseClickMsg:
		if m.mode == modeDashboard && msg.Button == tea.MouseLeft {
			if idx := m.tileAt(msg.X, msg.Y); idx >= 0 {
				m.selected = idx
				return m.openTile(idx)
			}
		}
		return m, nil

	case boundMsg:
		// Dropped when the environment has moved on while this was resolving: an
		// operator who flipped twice in a second must not end up with the first
		// environment's values under the second one's name.
		//
		// By stamp, not by name, for the reason the stamp exists at all: an
		// edit to the environment already switched on leaves the name identical
		// and changes the answer, so a bind started before the edit would
		// otherwise be accepted over the one started after it.
		if msg.stamp != m.boundStamp {
			return m, nil
		}
		m.bound = msg.bound
		if m.mode == modeDashboard {
			m.tickGen++
			return m, refreshTiles(m.tiles, m.tickGen, m.pluginCfg, m.profileFor)
		}
		return m, nil

	case tickMsg:
		// Refresh only while the dashboard is visible, and only the chain
		// currently in force — anything else is a return trip's predecessor,
		// left ticking after a later visit already restarted it, and letting
		// it re-arm here is exactly how the count of live timers used to
		// grow with every trip through browse and back.
		if m.mode == modeDashboard && msg.gen == m.tickGen {
			// Re-read the switch on the way past. A deadline lapses without
			// anybody touching the keyboard, and `rta use` in another terminal
			// is somebody changing environments without leaving this one — both
			// have to reach the screen, and this is the only thing that runs
			// while nothing is happening. Cheap unless the name actually moved.
			bind := m.syncActive()
			m.tickGen++
			return m, tea.Batch(bind, refreshTiles(m.tiles, m.tickGen, m.pluginCfg, m.profileFor))
		}
		return m, nil

	case resultMsg:
		// A result the user walked away from must not paint over what they
		// walked to.
		if msg.seq != 0 && msg.seq != m.runSeq {
			return m, nil
		}
		// Cleaned once, at the top, rather than at each place a string is
		// drawn — and above every branch below, because the flash path returns
		// early and would otherwise draw a raw one-liner.
		//
		// cli.Render sanitises its own local copy, so everything the TUI draws
		// *around* that copy was raw: resultMeta prepends Sections item titles
		// in rta's own styling, and a title carrying an OSC 8 hyperlink went to
		// the terminal verbatim — a live link with attacker-chosen text and
		// target, inside rta's panel border, in rta's voice.
		//
		// Worse than a display bug: runAction takes a row's identity from
		// m.result.view while the cell on screen came from the sanitised copy,
		// so what was shown and what was acted on were different strings by
		// construction. Cleaning at ingress makes them the same string instead
		// of making two readers agree, which is the version that stays true
		// when a third is added.
		msg.view = view.MapStrings(msg.view, textclean.Terminal)
		msg.err = view.MapErrorStrings(msg.err, textclean.Terminal)
		// A mutating action finished cleanly: flash its outcome and return
		// to the view it was launched from, reloaded. If it destroyed that
		// view's subject (removing the very task whose page we were on),
		// come back one level further instead of reloading a record that no
		// longer exists.
		if m.refreshPending && msg.err == nil && !m.isTop(msg.cap) {
			m.refreshPending = false
			m.flash = flashText(msg)
			if m.subjectGone {
				m.subjectGone = false
				m.trail = m.trail[:len(m.trail)-1]
			}
			if len(m.trail) > 0 {
				return m.reopenTop()
			}
			return m.closeToOrigin()
		}
		m.refreshPending, m.subjectGone = false, false
		m.mode = modeResult
		m.current = msg.cap
		m.result = msg
		m.enterTrail(msg.cap, m.lastValues)
		tail := false
		if tbl, ok := msg.view.(view.Table); ok {
			m.row = min(m.row, max(len(tbl.Rows)-1, 0))
			// A log opens where things are now — its last row — and is
			// walked back from there. On a refresh too: the newest row is
			// the one that changed, so the cursor goes to it rather than
			// staying on whatever row it was.
			if tbl.Tail {
				m.row, tail = max(len(tbl.Rows)-1, 0), true
			}
		}
		m.renderResult()
		if tail {
			m.viewport.GotoBottom()
		} else {
			m.viewport.GotoTop()
		}
		return m, nil

	case tea.KeyPressMsg:
		m.flash = ""
		// Routed per pane (dispatch.go). A key the pane did not consume falls
		// through to its passthrough below — the embedded list, form or
		// viewport — exactly as the unmatched switch arms used to.
		if nm, cmd, done := m.keyPress(msg); done {
			return nm, cmd
		}
	}

	var cmd tea.Cmd
	switch m.mode {
	case modeBrowse:
		before := m.list.Index()
		m.list, cmd = m.list.Update(msg)
		// Put the cursor somewhere enter can act on: not a section label, and
		// not past the end of a list a filter just shortened.
		m.settleCursor(m.list.Index() >= before)
	case modeForm:
		return m.updateForm(msg)
	case modeTheme:
		return m.updateThemeForm(msg)
	case modeCopyPick:
		return m.updateCopyPick(msg)
	case modeResult:
		m.viewport, cmd = m.viewport.Update(msg)
	}
	return m, cmd
}

// closeToOrigin returns to wherever the current form/result was opened from,
// restarting the tile refresh loop when that is the dashboard.
func (m Model) closeToOrigin() (tea.Model, tea.Cmd) {
	// The environment may have moved while this screen was open — often
	// *because* it was open, since every profile editor closes through here.
	// Correctness does not rest on this line (the refresh tick re-reads the
	// stamp, and a run checks it at the point of use), but the window between
	// saving an edit and the screen behind the form agreeing with it does.
	bind := m.syncActive()
	m.mode = m.origin
	if m.origin == modeDashboard {
		m.tickGen++
		return m, tea.Batch(bind, refreshTiles(m.tiles, m.tickGen, m.pluginCfg, m.profileFor))
	}
	return m, bind
}

// openTile opens the selected dashboard tile: the search bar takes focus,
// capability tiles open their full result with the tile's own inputs.
func (m Model) openTile(idx int) (tea.Model, tea.Cmd) {
	if idx < 0 || idx >= len(m.tiles) {
		return m, nil
	}
	t := m.tiles[idx]
	if t.search {
		m.searchEditing = true
		return m, nil
	}
	m.origin = modeDashboard
	// A tile is Read by construction (buildTiles refuses anything else), so
	// this is the fast path rather than the gate. Anything that is not gets
	// the same form-and-confirm every other surface gives it.
	if t.cap.Safety != plugin.Read {
		return m.open(t.cap)
	}
	m.current = t.cap
	m.lastValues, m.lastYes = t.values, false
	m.trail = nil
	m.row = 0
	return m, m.startRun(t.cap, t.values, false)
}

// open decides what Enter does for a capability: form when there is anything
// to ask (inputs or a destructive confirmation), direct run otherwise.
func (m Model) open(c plugin.Capability) (tea.Model, tea.Cmd) {
	m.current = c
	m.trail = nil
	m.row = 0
	m.refreshPending = false
	if hasInputs(c) || c.Safety == plugin.Destructive {
		return m.startForm(c, nil)
	}
	m.lastValues, m.lastYes = nil, false
	return m, m.startRun(c, nil, false)
}

func (m Model) View() tea.View {
	var v tea.View
	switch m.mode {
	case modeDashboard:
		v = tea.NewView(m.dashboardView())
		v.MouseMode = tea.MouseModeCellMotion // clickable tiles
	case modeForm:
		v = tea.NewView(m.formView())
	case modeRunning:
		body := fmt.Sprintf("%s running %s …\n\n%s",
			m.spinner.View(), theme.Key.Render(m.current.ID), m.footerFor(modeRunning))
		if m.width > 0 && m.height > 0 {
			body = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, body)
		}
		v = tea.NewView(body)
	case modePlugins:
		v = tea.NewView(m.pluginsView())
	case modeProfiles:
		v = tea.NewView(m.profilesView())
	case modeProfilePlugins:
		v = tea.NewView(m.connsView())
	case modeTheme:
		v = tea.NewView(m.themeView())
	case modeCopyPick:
		v = tea.NewView(m.copyPickView())
	case modeResult:
		v = tea.NewView(m.resultView())
		v.MouseMode = tea.MouseModeCellMotion // wheel scrolls long output
	case modeBrowse:
		v = tea.NewView(m.browseView())
		v.MouseMode = tea.MouseModeCellMotion
	default:
		v = tea.NewView(m.list.View())
		v.MouseMode = tea.MouseModeCellMotion
	}
	v.AltScreen = true
	return v
}

// Run starts the TUI program.
func Run(ctx context.Context, reg *registry.Registry, dash config.Dashboard,
	pluginCfg func(namespace string) map[string]any, opts ...Option) error {
	// Explicit input: main() has pointed os.Stdin at /dev/null so that no
	// plugin inherits the user's keyboard, and bubbletea's default is
	// os.Stdin — without this the TUI would open and answer no key at all.
	_, err := tea.NewProgram(New(reg, dash, pluginCfg, opts...),
		tea.WithContext(ctx), tea.WithInput(stdio.Real())).Run()
	return err
}
