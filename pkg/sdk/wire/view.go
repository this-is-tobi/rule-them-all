package wire

import (
	"github.com/this-is-tobi/rta/pkg/view"
	rtav1 "github.com/this-is-tobi/rta/proto/rta/v1"
)

// columnKinds is the whole ColumnKind mapping, in one place and in both
// directions, so a kind cannot be added to the encoder and forgotten in the
// decoder. A kind the decoder does not know becomes plain text rather than an
// error: an older host reading a newer plugin should render the column, not
// refuse the result, and text is what a column with no hint already means.
var columnKinds = []struct {
	go_ view.ColumnKind
	pb  rtav1.ColumnKind
}{
	{view.KindText, rtav1.ColumnKind_COLUMN_KIND_UNSPECIFIED},
	{view.KindNumber, rtav1.ColumnKind_COLUMN_KIND_NUMBER},
	{view.KindBytes, rtav1.ColumnKind_COLUMN_KIND_BYTES},
	{view.KindPercent, rtav1.ColumnKind_COLUMN_KIND_PERCENT},
	{view.KindDuration, rtav1.ColumnKind_COLUMN_KIND_DURATION},
	{view.KindTimestamp, rtav1.ColumnKind_COLUMN_KIND_TIMESTAMP},
	{view.KindStatus, rtav1.ColumnKind_COLUMN_KIND_STATUS},
	{view.KindUsage, rtav1.ColumnKind_COLUMN_KIND_USAGE},
}

func columnKindToProto(k view.ColumnKind) rtav1.ColumnKind {
	for _, m := range columnKinds {
		if m.go_ == k {
			return m.pb
		}
	}
	return rtav1.ColumnKind_COLUMN_KIND_UNSPECIFIED
}

func columnKindFromProto(k rtav1.ColumnKind) view.ColumnKind {
	for _, m := range columnKinds {
		if m.pb == k {
			return m.go_
		}
	}
	return view.KindText
}

var chartKinds = []struct {
	go_ view.ChartKind
	pb  rtav1.ChartKind
}{
	{view.ChartLine, rtav1.ChartKind_CHART_KIND_LINE},
	{view.ChartBar, rtav1.ChartKind_CHART_KIND_BAR},
}

func chartKindToProto(k view.ChartKind) rtav1.ChartKind {
	for _, m := range chartKinds {
		if m.go_ == k {
			return m.pb
		}
	}
	return rtav1.ChartKind_CHART_KIND_UNSPECIFIED
}

func chartKindFromProto(k rtav1.ChartKind) view.ChartKind {
	for _, m := range chartKinds {
		if m.pb == k {
			return m.go_
		}
	}
	// Not a guess with a default: an unrecognised kind stays unrecognised,
	// and every renderer already refuses to draw a chart whose kind it does
	// not know rather than picking one.
	return ""
}

// ErrorToProto encodes a *view.Error. nil in, nil out.
func ErrorToProto(e *view.Error) *rtav1.Error {
	if e == nil {
		return nil
	}
	return &rtav1.Error{
		Code:      e.Code,
		Message:   e.Message,
		Hint:      e.Hint,
		Retryable: e.Retryable,
		Refusal:   e.Refusal,
	}
}

// ErrorFromProto decodes an Error. nil in, nil out.
func ErrorFromProto(e *rtav1.Error) *view.Error {
	if e == nil {
		return nil
	}
	return &view.Error{
		Code:      e.GetCode(),
		Message:   e.GetMessage(),
		Hint:      e.GetHint(),
		Retryable: e.GetRetryable(),
		Refusal:   e.GetRefusal(),
	}
}

// ViewToProto encodes a view.
//
// A nil view encodes as a View with no kind set, which is legal and means
// "nothing to show" — a handler that returned no view, or a section with a
// heading and nothing under it. It is not an error and no renderer treats it
// as one.
func ViewToProto(v view.View) *rtav1.View {
	switch t := v.(type) {
	case nil:
		return &rtav1.View{}
	case view.Text:
		return &rtav1.View{Kind: &rtav1.View_Text{Text: &rtav1.Text{
			Body: t.Body, Markdown: t.Markdown,
		}}}
	case view.KeyValue:
		return &rtav1.View{Kind: &rtav1.View_KeyValue{KeyValue: &rtav1.KeyValue{
			Pairs: mapSlice(t.Pairs, func(p view.Pair) *rtav1.Pair {
				return &rtav1.Pair{Key: p.Key, Value: p.Value}
			}),
			Redacted: t.Redacted,
		}}}
	case view.Table:
		tbl := &rtav1.Table{
			Columns: mapSlice(t.Columns, func(c view.Column) *rtav1.Column {
				return &rtav1.Column{Name: c.Name, Kind: columnKindToProto(c.Kind)}
			}),
			Rows: mapSlice(t.Rows, func(r []string) *rtav1.Row {
				return &rtav1.Row{Cells: r}
			}),
			Total:    int32(t.Total),
			Redacted: t.Redacted,
			Tail:     t.Tail,
		}
		if t.Page != nil {
			tbl.Page = &rtav1.Cursor{Next: t.Page.Next}
		}
		return &rtav1.View{Kind: &rtav1.View_Table{Table: tbl}}
	case view.Tree:
		return &rtav1.View{Kind: &rtav1.View_Tree{Tree: &rtav1.Tree{
			Roots: nodesToProto(t.Roots),
		}}}
	case view.Chart:
		return &rtav1.View{Kind: &rtav1.View_Chart{Chart: &rtav1.Chart{
			Kind: chartKindToProto(t.Kind),
			Series: mapSlice(t.Series, func(s view.Series) *rtav1.Series {
				return &rtav1.Series{Name: s.Name, Points: s.Points}
			}),
			Unit: t.Unit, Max: t.Max,
		}}}
	case view.Sections:
		return &rtav1.View{Kind: &rtav1.View_Sections{Sections: &rtav1.Sections{
			Items: mapSlice(t.Items, func(s view.Section) *rtav1.Section {
				return &rtav1.Section{Id: s.ID, Title: s.Title, View: ViewToProto(s.View)}
			}),
			Warnings: mapSlice(t.Warnings, func(w view.Error) *rtav1.Error {
				return ErrorToProto(&w)
			}),
		}}}
	case *view.Error:
		return &rtav1.View{Kind: &rtav1.View_Error{Error: ErrorToProto(t)}}
	}
	// A type outside the union. The Go interface is closed by an unexported
	// method so this is unreachable from outside pkg/view, and encoding it as
	// "nothing to show" is the same thing every renderer already does with a
	// view it cannot name.
	return &rtav1.View{}
}

func nodesToProto(in []view.Node) []*rtav1.Node {
	return mapSlice(in, func(n view.Node) *rtav1.Node {
		return &rtav1.Node{Label: n.Label, Detail: n.Detail, Children: nodesToProto(n.Children)}
	})
}

// ViewFromProto decodes a view. An unset kind decodes to nil, which every
// renderer treats as "nothing to show".
func ViewFromProto(v *rtav1.View) view.View {
	if v == nil {
		return nil
	}
	switch k := v.Kind.(type) {
	case *rtav1.View_Text:
		return view.Text{Body: k.Text.GetBody(), Markdown: k.Text.GetMarkdown()}
	case *rtav1.View_KeyValue:
		return view.KeyValue{
			Pairs: mapSlice(k.KeyValue.GetPairs(), func(p *rtav1.Pair) view.Pair {
				return view.Pair{Key: p.GetKey(), Value: p.GetValue()}
			}),
			Redacted: k.KeyValue.GetRedacted(),
		}
	case *rtav1.View_Table:
		t := view.Table{
			Columns: mapSlice(k.Table.GetColumns(), func(c *rtav1.Column) view.Column {
				return view.Column{Name: c.GetName(), Kind: columnKindFromProto(c.GetKind())}
			}),
			Rows: mapSlice(k.Table.GetRows(), func(r *rtav1.Row) []string {
				return r.GetCells()
			}),
			Total:    int(k.Table.GetTotal()),
			Redacted: k.Table.GetRedacted(),
			Tail:     k.Table.GetTail(),
		}
		if p := k.Table.GetPage(); p != nil {
			t.Page = &view.Cursor{Next: p.GetNext()}
		}
		return t
	case *rtav1.View_Tree:
		return view.Tree{Roots: nodesFromProto(k.Tree.GetRoots())}
	case *rtav1.View_Chart:
		return view.Chart{
			Kind: chartKindFromProto(k.Chart.GetKind()),
			Series: mapSlice(k.Chart.GetSeries(), func(s *rtav1.Series) view.Series {
				return view.Series{Name: s.GetName(), Points: s.GetPoints()}
			}),
			Unit: k.Chart.GetUnit(),
			Max:  k.Chart.GetMax(),
		}
	case *rtav1.View_Sections:
		return view.Sections{
			Items: mapSlice(k.Sections.GetItems(), func(s *rtav1.Section) view.Section {
				return view.Section{ID: s.GetId(), Title: s.GetTitle(), View: ViewFromProto(s.GetView())}
			}),
			Warnings: mapSlice(k.Sections.GetWarnings(), func(w *rtav1.Error) view.Error {
				// Not reachable from the wire — proto.Unmarshal turns a nil
				// element into an empty message, verified — but this is a
				// public package, and a nil deref here would take the host
				// down over a value an embedder can construct by hand.
				if e := ErrorFromProto(w); e != nil {
					return *e
				}
				return view.Error{}
			}),
		}
	case *rtav1.View_Error:
		return ErrorFromProto(k.Error)
	}
	return nil
}

func nodesFromProto(in []*rtav1.Node) []view.Node {
	return mapSlice(in, func(n *rtav1.Node) view.Node {
		return view.Node{Label: n.GetLabel(), Detail: n.GetDetail(), Children: nodesFromProto(n.GetChildren())}
	})
}
