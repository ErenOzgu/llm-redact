// Package redact masks sensitive values in text with numbered placeholders and puts them back.
package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Options select what is masked.
type Options struct {
	Only        map[string]bool // when not empty, mask only these kinds
	Skip        map[string]bool // never mask these kinds
	Keep        map[string]bool // literal values that are never masked
	Custom      []CustomRule    // extra patterns
	AllowAnyway bool            // go on although the input already contains placeholder-like text
}

// CustomRule is a user-supplied pattern. Group 0 is the whole match.
type CustomRule struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Group   int    `json:"group"`
}

// Finding is one thing the redactor found.
type Finding struct {
	Kind       string
	Start, End int // byte offsets in the input
	Line, Col  int // 1-based, in bytes
	Value      string
}

// Redactor masks text. It is not safe for concurrent use.
type Redactor struct {
	opts Options
	dets []detector
	// Map is where placeholders and their values are kept.
	Map *Mapping
}

// ErrCollision is returned when the input already contains text that looks like one of our
// placeholders but is not in the mapping: restoring would be ambiguous.
type ErrCollision struct{ Examples []string }

func (e *ErrCollision) Error() string {
	return fmt.Sprintf("the input already contains text that looks like a placeholder (%s); "+
		"restoring would be ambiguous (use the force option to go on anyway)", strings.Join(e.Examples, ", "))
}

var kindNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*$`)

// New returns a Redactor. m may be nil for a fresh mapping.
func New(opts Options, m *Mapping) (*Redactor, error) {
	if m == nil {
		m = NewMapping()
	}
	r := &Redactor{opts: opts, Map: m}
	for k := range opts.Only {
		if !known(k) {
			return nil, fmt.Errorf("unknown kind %q (see the list command)", k)
		}
	}
	for k := range opts.Skip {
		if !known(k) {
			return nil, fmt.Errorf("unknown kind %q (see the list command)", k)
		}
	}
	for _, d := range builtinDetectors() {
		if r.enabled(d.kind) {
			r.dets = append(r.dets, d)
		}
	}
	for _, c := range opts.Custom {
		if !kindNameRE.MatchString(c.Kind) {
			return nil, fmt.Errorf("custom rule kind %q must be upper case letters and digits, starting with a letter", c.Kind)
		}
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			return nil, fmt.Errorf("custom rule %s: %w", c.Kind, err)
		}
		if c.Group < 0 || c.Group > re.NumSubexp() {
			return nil, fmt.Errorf("custom rule %s: pattern has no group %d", c.Kind, c.Group)
		}
		kind, group := c.Kind, c.Group
		if r.enabled(kind) {
			r.dets = append(r.dets, detector{kind, prioCustom, func(s string) []span {
				return groupSpans(re, s, kind, prioCustom, group)
			}})
		}
	}
	return r, nil
}

func known(kind string) bool {
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func (r *Redactor) enabled(kind string) bool {
	if len(r.opts.Only) > 0 && !r.opts.Only[kind] {
		return false
	}
	return !r.opts.Skip[kind]
}

// find returns the non-overlapping spans to mask, in order of position.
func (r *Redactor) find(s string) []span {
	var all []span
	for _, d := range r.dets {
		all = append(all, d.find(s)...)
	}
	kept := all[:0]
	for _, sp := range all {
		v := s[sp.start:sp.end]
		if r.opts.Keep[v] || exactPlaceholderRE.MatchString(v) {
			continue
		}
		kept = append(kept, sp)
	}
	// The strongest detector wins; among equals the longer span does; then the earlier one.
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if a.prio != b.prio {
			return a.prio > b.prio
		}
		if la, lb := a.end-a.start, b.end-b.start; la != lb {
			return la > lb
		}
		return a.start < b.start
	})
	var chosen []span
	for _, sp := range kept {
		overlaps := false
		for _, c := range chosen {
			if sp.start < c.end && c.start < sp.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			chosen = append(chosen, sp)
		}
	}
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].start < chosen[j].start })
	return chosen
}

// Scan reports what would be masked, without masking it and without touching the mapping.
func (r *Redactor) Scan(s string) []Finding {
	spans := r.find(s)
	out := make([]Finding, 0, len(spans))
	line, lineStart, pos := 1, 0, 0
	for _, sp := range spans {
		for ; pos < sp.start; pos++ {
			if s[pos] == '\n' {
				line++
				lineStart = pos + 1
			}
		}
		out = append(out, Finding{Kind: sp.kind, Start: sp.start, End: sp.end, Line: line, Col: sp.start - lineStart + 1, Value: s[sp.start:sp.end]})
	}
	return out
}

// Redact masks s. The returned findings carry the original values.
func (r *Redactor) Redact(s string) (string, []Finding, error) {
	literals := map[string]bool{}
	var unknown []string
	for _, m := range placeholderRE.FindAllString(s, -1) {
		key := normalizePlaceholder(m)
		literals[key] = true
		if _, ok := r.Map.Entries[key]; !ok && len(unknown) < 3 {
			unknown = append(unknown, m)
		}
	}
	if len(unknown) > 0 && !r.opts.AllowAnyway {
		return "", nil, &ErrCollision{Examples: unknown}
	}
	found := r.Scan(s)
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, f := range found {
		b.WriteString(s[prev:f.Start])
		b.WriteString(r.Map.placeholder(f.Kind, f.Value, literals))
		prev = f.End
	}
	b.WriteString(s[prev:])
	return b.String(), found, nil
}
