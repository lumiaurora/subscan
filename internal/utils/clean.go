package utils

import "strings"

func NormalizeEntries(entries []string) []string {
	normalized := make([]string, 0, len(entries))

	for _, entry := range entries {
		name := strings.ToLower(strings.TrimSpace(entry))
		if name == "" {
			continue
		}

		name = strings.TrimSuffix(name, ".")
		for strings.HasPrefix(name, "*.") {
			name = strings.TrimPrefix(name, "*.")
		}

		normalized = append(normalized, name)
	}

	return normalized
}

func Deduplicate(entries []string) []string {
	seen := make(map[string]struct{}, len(entries))
	unique := make([]string, 0, len(entries))

	for _, entry := range entries {
		if entry == "" {
			continue
		}

		if _, ok := seen[entry]; ok {
			continue
		}

		seen[entry] = struct{}{}
		unique = append(unique, entry)
	}

	return unique
}
