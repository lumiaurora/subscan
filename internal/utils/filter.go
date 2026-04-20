package utils

import "strings"

func FilterSubdomains(entries []string, domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	suffix := "." + domain
	filtered := make([]string, 0, len(entries))

	for _, entry := range entries {
		if entry == "" || entry == domain {
			continue
		}

		if strings.HasSuffix(entry, suffix) {
			filtered = append(filtered, entry)
		}
	}

	return filtered
}
