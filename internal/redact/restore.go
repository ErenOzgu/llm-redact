package redact

import (
	"strconv"
	"strings"
)

// normalizePlaceholder turns "[[ip_01]]" into "[[IP_1]]", the form used as a key in the mapping.
func normalizePlaceholder(ph string) string {
	sub := placeholderRE.FindStringSubmatch(ph)
	if sub == nil {
		return ph
	}
	n, err := strconv.Atoi(sub[2])
	if err != nil {
		return ph
	}
	return "[[" + strings.ToUpper(sub[1]) + "_" + strconv.Itoa(n) + "]]"
}

// Restore puts the original values back into s. Placeholders that are not in the mapping are left
// as they are and returned, so the caller can warn about them.
func Restore(s string, m *Mapping) (string, []string) {
	var unknown []string
	seen := map[string]bool{}
	out := placeholderRE.ReplaceAllStringFunc(s, func(ph string) string {
		key := normalizePlaceholder(ph)
		if v, ok := m.Entries[key]; ok {
			return v
		}
		if !seen[key] {
			seen[key] = true
			unknown = append(unknown, ph)
		}
		return ph
	})
	return out, unknown
}
