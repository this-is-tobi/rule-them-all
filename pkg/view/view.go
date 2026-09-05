// Package view defines the renderer-agnostic result types returned by
// capabilities. Views carry data and semantic hints only — never ANSI codes,
// colors, or layout. Rendering decisions belong to the host (CLI, TUI, MCP,
// web), which is what lets one capability serve every surface.
//
// Contract rules:
//   - Every View must be expressible as plain text, JSON, and an MCP result.
//   - Tables are paginated at the contract level.
//   - Secrets are marked Redacted by the producer and masked by the host.
package view

// View is the closed union of result types a capability can return.
//
// A nil View is legal everywhere one is accepted: a handler may return
// (nil, nil) to mean "nothing to show", a Section may carry a title and no
// view, and every renderer skips it rather than treating it as an error. It
// encodes as {"type":"unknown"}.
type View interface{ isView() }

// Text is free-form text, optionally markdown to be rendered by the host.
type Text struct {
	Body     string `json:"body"`
	Markdown bool   `json:"markdown,omitempty"`
}

// Pair is a single key/value entry.
type Pair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// KeyValue is a flat set of labelled values (host info, cert summary, ...).
type KeyValue struct {
	Pairs []Pair `json:"pairs"`
	// Redacted lists keys whose values must be masked by every renderer.
	Redacted []string `json:"redacted,omitempty"`
}

// ColumnKind is a semantic hint about what a column holds. It selects
// alignment, and for KindStatus and KindUsage the vocabulary a renderer
// grades by.
//
// It never formats a cell. A view carries pre-formatted strings, so a column
// declaring KindBytes still receives whatever its producer put there —
// `1392640` if that is what the producer wrote. pkg/format is the shared
// vocabulary for writing it as `1.3 MiB` instead, and it is the producer's
// job to call it. The first version of this comment said "formatted/aligned",
// which read as a promise the renderer does not keep.
type ColumnKind string

const (
	KindText      ColumnKind = ""
	KindNumber    ColumnKind = "number"
	KindBytes     ColumnKind = "bytes"
	KindPercent   ColumnKind = "percent"
	KindDuration  ColumnKind = "duration"
	KindTimestamp ColumnKind = "timestamp"
	KindStatus    ColumnKind = "status"
	// KindUsage is how much of a capacity is taken, as a percentage, where
	// approaching 100 is approaching a limit: a disk filling, a quota running
	// out, a container nearing the memory ceiling it will be killed at.
	//
	// Separate from KindPercent, rather than a grading rule applied to it,
	// because a percentage does not on its own say which end is the bad one —
	// and most of the ones in this codebase have no bad end at all.
	// fs.usage's Share is a directory's proportion of a total, and one entry
	// holding 95% of a disk is a finding about the shape of the tree, not a
	// problem. sys ps's CPU% passes 100 on a second core. And
	// kube.metrics.pressure's columns are PSI stall time, where a node is in
	// real trouble an order of magnitude below where a disk gets interesting,
	// so grading it against a disk's thresholds would paint a sick node green.
	// A hint that graded every percentage would be wrong about more columns
	// than it was right about, which makes this the one to opt into.
	KindUsage ColumnKind = "usage"
)

// UsageWarn and UsageBad are the bands a KindUsage column is graded in: below
// warn is comfortable, at or above bad is out of room. Renderers still choose
// what a band looks like — the contract states only where the boundaries are.
//
// They live here, in the contract, rather than in a renderer because two
// unrelated things need them and only one of them renders: `sys disk` says
// "WARN >80%" in a Status column beside its Use%, which is the half of the
// signal that survives a pipe, a --no-color terminal and --output json. Those
// two must agree about the same disk, and the way this codebase has already
// been bitten by that is x509check — a package that exists because `cert` and
// `audit` once disagreed about the same certificate's expiry window.
const (
	UsageWarn = 80.0
	UsageBad  = 90.0
)

// Column describes one table column.
type Column struct {
	Name string     `json:"name"`
	Kind ColumnKind `json:"kind,omitempty"`
}

// Cursor carries contract-level pagination state.
type Cursor struct {
	Next string `json:"next,omitempty"`
}

// Table is tabular data. Rows hold pre-formatted cell values; Total reports
// how many rows exist overall (>= len(Rows) when paginated).
type Table struct {
	Columns []Column   `json:"columns"`
	Rows    [][]string `json:"rows"`
	Total   int        `json:"total,omitempty"`
	Page    *Cursor    `json:"page,omitempty"`
	// Redacted names columns whose cells must be masked by every renderer.
	// Column names rather than indices, so that reordering the columns cannot
	// silently move the protection to the wrong one — and the same spelling
	// KeyValue already uses, because it is the same idea.
	Redacted []string `json:"redacted,omitempty"`
	// Tail says the rows are in time order with the newest last. Every
	// surface prints them in that order — a log ends where things are now
	// and is walked backwards — and a surface that scrolls opens on the last
	// row rather than the first, which for a record is the oldest thing in
	// it. Declared by the view, not inferred from a timestamp column, so a
	// table of expiries in ascending order is not mistaken for a log.
	Tail bool `json:"tail,omitempty"`
}

// ChartKind selects how series are drawn.
type ChartKind string

const (
	ChartLine ChartKind = "line" // each series is a sequence of points
	ChartBar  ChartKind = "bar"  // each series is one labelled value
)

// Series is one named data series.
//
// For ChartBar, Points holds the single value the bar's length encodes; a
// bar is one labelled quantity by definition, so any further points are
// ignored rather than silently averaged or summed.
type Series struct {
	Name   string    `json:"name"`
	Points []float64 `json:"points"`
}

// Chart is numeric data with a drawing hint. Like every view it stays pure
// data: renderers decide glyphs, colors and size.
type Chart struct {
	Kind   ChartKind `json:"kind"`
	Series []Series  `json:"series"`
	// Unit annotates values, e.g. "ms" or "%".
	Unit string `json:"unit,omitempty"`
	// Max, when > 0, fixes the top of the scale — 100 for percentages — so
	// that four idle cores are not drawn at full height, and so two renders
	// of the same metric can be compared to each other.
	//
	// It belongs to the chart rather than to each series because that is the
	// only place it can mean anything: the series share one axis. Declared
	// per-series it read as a promise no renderer could keep. The one that
	// existed took the maximum across every series and applied it to all of
	// them, so "this series is a percentage, that one is milliseconds" was
	// expressible, accepted, and silently wrong — and the line path ignored
	// it outright, making the documented guarantee false for half of
	// ChartKind.
	Max float64 `json:"max,omitempty"`
}

// Node is one node of a Tree.
type Node struct {
	Label    string `json:"label"`
	Detail   string `json:"detail,omitempty"`
	Children []Node `json:"children,omitempty"`
}

// Tree is hierarchical data (schemas, key prefixes, cert chains, ...).
type Tree struct {
	Roots []Node `json:"roots"`
}

// Section is one titled part of a composite view.
//
// Title is what a reader sees, and is therefore free to change: rewording a
// heading is UX work, not an API break. ID is what everything else addresses
// the section by — a script pulling one section out of a page, an agent
// citing which section a fact came from. With Title doing both jobs, every
// wording improvement was a silent breaking change for whoever had scripted
// against the old one, and the tension resolved by never improving wording.
//
// ID is optional and Key falls back to Title, so a section pays for
// stability only when it wants it.
type Section struct {
	ID    string `json:"id,omitempty"`
	Title string `json:"title"`
	View  View   `json:"view"`
}

// Key is the stable handle for this section: ID when the producer set one,
// otherwise Title. Machine consumers address sections by Key; renderers
// display Title.
func (s Section) Key() string {
	if s.ID != "" {
		return s.ID
	}
	return s.Title
}

// Sections composes other views into one structured page — the component
// model of this system. A rich detail page is not a bespoke rendering: it is
// an arrangement of the very views individual capabilities already return,
// so `sys overview --detail` is literally sys.host + sys.cpu + sys.mem + …
// assembled. Composites nest, and every renderer walks them recursively.
//
// This is also the shape a component-driven surface consumes: each Section
// maps to one component with a typed payload, which is the seam a future
// component-driven surface plugs into.
type Sections struct {
	Items []Section `json:"items"`
	// Warnings carries what the page could not produce, so that a partial
	// report says it is partial.
	//
	// Dropping a section whose handler failed is the right default — one
	// absent sensor should not cost the reader the six that answered — but
	// it left "this platform has no such sensor" and "this sensor errored"
	// looking identical from outside: both are simply a heading that is not
	// there. Neither a person nor a machine consumer could tell a complete
	// page from a degraded one, and a degraded page that looks complete is
	// how a monitoring check comes back green.
	Warnings []Error `json:"warnings,omitempty"`
}

func (Text) isView()     {}
func (KeyValue) isView() {}
func (Table) isView()    {}
func (Tree) isView()     {}
func (Chart) isView()    {}
func (Sections) isView() {}

// Mask is the placeholder every renderer substitutes for redacted values.
const Mask = "••••••"

// IsRedacted reports whether the given key is marked redacted.
func (kv KeyValue) IsRedacted(key string) bool { return named(kv.Redacted, key) }

// IsRedacted reports whether the named column is marked redacted.
func (t Table) IsRedacted(column string) bool { return named(t.Redacted, column) }

func named(list []string, name string) bool {
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

// Redact returns a copy of v with redacted values masked. It is the single
// enforcement point for the contract's redaction promise — the host masks
// redacted values in TUI, CLI, logs and MCP output alike, so every renderer
// that turns a View into bytes a caller can read must run it first,
// including the MCP bridge, which callers can reach without a human present.
//
// It recurses through Sections. A composite page is assembled from the very
// views other capabilities return, so a KeyValue that masks a field on its
// own must keep masking it once some detail page embeds it — otherwise
// composing a view would quietly strip its protection, and the safest thing
// a producer can do (mark a field Redacted) would be undone by the safest
// thing a consumer can do (reuse an existing view).
//
// KeyValue and Table are the two shapes that can declare a secret, because
// they are the two with a stable name to hang the declaration on: a key, or a
// column. The others deliberately cannot, and the reason is worth stating so
// that "add Redacted to it" is not the reflex when one of them next carries
// something sensitive:
//
//   - Text is a body, not fields. Marking a substring secret would mean the
//     contract carrying offsets or patterns into free prose — the producer is
//     the only party that knows what it wrote, so the producer masks it.
//   - Tree is labelled structure whose node names are paths, hosts and
//     certificate subjects. If a value ever needs masking there, it belongs in
//     a KeyValue or a Table instead; a secret is a field, and a field in a
//     tree is a modelling mistake, not a redaction gap.
//   - Chart is numbers. A number that must not be seen is not a chart.
func Redact(v View) View {
	switch t := v.(type) {
	case KeyValue:
		if len(t.Redacted) == 0 {
			return v
		}
		pairs := make([]Pair, len(t.Pairs))
		copy(pairs, t.Pairs)
		for i, p := range pairs {
			if t.IsRedacted(p.Key) {
				pairs[i].Value = Mask
			}
		}
		t.Pairs = pairs
		return t
	case Table:
		if len(t.Redacted) == 0 {
			return v
		}
		mask := make([]bool, len(t.Columns))
		for i, c := range t.Columns {
			mask[i] = t.IsRedacted(c.Name)
		}
		rows := make([][]string, len(t.Rows))
		for i, row := range t.Rows {
			cells := make([]string, len(row))
			copy(cells, row)
			// Rows are allowed to be shorter or longer than the column list;
			// a cell with no column cannot be named, so it cannot be masked.
			for j := range cells {
				if j < len(mask) && mask[j] {
					cells[j] = Mask
				}
			}
			rows[i] = cells
		}
		t.Rows = rows
		return t
	case Sections:
		items := make([]Section, len(t.Items))
		for i, s := range t.Items {
			if s.View != nil {
				s.View = Redact(s.View)
			}
			items[i] = s
		}
		t.Items = items
		return t
	}
	return v
}
