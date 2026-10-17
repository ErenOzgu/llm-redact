package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// placeholderRE matches the placeholders this package writes: [[KIND_N]]. The match is case
// insensitive because a model that repeats a placeholder sometimes changes its case.
var placeholderRE = regexp.MustCompile(`(?i)\[\[([A-Z][A-Z0-9]*)_([0-9]+)\]\]`)

// exactPlaceholderRE matches a whole string that is one placeholder.
var exactPlaceholderRE = regexp.MustCompile(`(?i)^\[\[[A-Z][A-Z0-9]*_[0-9]+\]\]$`)

// Mapping remembers which value stands behind which placeholder. The same value of the same kind
// always gets the same placeholder, also across several runs that share one mapping file.
type Mapping struct {
	Version int               `json:"version"`
	Entries map[string]string `json:"entries"` // "[[IP_1]]" -> "10.20.30.40"

	rev  map[string]string // kind + "\x00" + value -> placeholder
	next map[string]int    // kind -> highest number handed out
}

// NewMapping returns an empty mapping.
func NewMapping() *Mapping {
	return &Mapping{Version: 1, Entries: map[string]string{}, rev: map[string]string{}, next: map[string]int{}}
}

// LoadMapping reads a mapping file. A file that does not exist yields an empty mapping, so the same
// command line works for the first and for every later run.
func LoadMapping(path string) (*Mapping, error) {
	m := NewMapping()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var disk Mapping
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("%s: not a mapping file: %w", path, err)
	}
	if disk.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported mapping version %d", path, disk.Version)
	}
	for ph, val := range disk.Entries {
		kind, n, ok := splitPlaceholder(ph)
		if !ok {
			return nil, fmt.Errorf("%s: %q is not a placeholder", path, ph)
		}
		m.Entries[ph] = val
		m.rev[kind+"\x00"+val] = ph
		if n > m.next[kind] {
			m.next[kind] = n
		}
	}
	return m, nil
}

// Save writes the mapping with mode 0600. The file holds every secret that was masked, so it is as
// sensitive as the input was.
func (m *Mapping) Save(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".llm-redact-map-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Len is the number of masked values.
func (m *Mapping) Len() int { return len(m.Entries) }

// placeholder returns the placeholder for a value, allocating one the first time. Numbers that are
// in skip (placeholder-looking text that was already in the input) are never handed out.
func (m *Mapping) placeholder(kind, value string, skip map[string]bool) string {
	key := kind + "\x00" + value
	if ph, ok := m.rev[key]; ok {
		return ph
	}
	for {
		m.next[kind]++
		ph := "[[" + kind + "_" + strconv.Itoa(m.next[kind]) + "]]"
		if skip[strings.ToUpper(ph)] {
			continue
		}
		m.Entries[ph] = value
		m.rev[key] = ph
		return ph
	}
}

// Counts returns how many distinct values of each kind are in the mapping.
func (m *Mapping) Counts() map[string]int {
	out := map[string]int{}
	for ph := range m.Entries {
		if kind, _, ok := splitPlaceholder(ph); ok {
			out[kind]++
		}
	}
	return out
}

// SortedKinds returns the keys of a count map in a stable order.
func SortedKinds(counts map[string]int) []string {
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

func splitPlaceholder(ph string) (kind string, n int, ok bool) {
	sub := placeholderRE.FindStringSubmatch(ph)
	if sub == nil || sub[0] != ph {
		return "", 0, false
	}
	n, err := strconv.Atoi(sub[2])
	if err != nil {
		return "", 0, false
	}
	return strings.ToUpper(sub[1]), n, true
}
