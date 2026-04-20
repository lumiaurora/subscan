package sources

import (
	"fmt"
	"net/url"
	"regexp"
)

func FetchRapidDNS(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", url.PathEscape(domain))

	body, err := fetchText(requestURL)
	if err != nil {
		return nil, err
	}

	pattern := regexp.MustCompile(`(?i)<td>\s*([a-z0-9*_.-]+\.` + regexp.QuoteMeta(domain) + `)\s*</td>`)
	matches := pattern.FindAllStringSubmatch(body, -1)
	results := make([]string, 0, len(matches))

	for _, match := range matches {
		if len(match) > 1 {
			results = append(results, match[1])
		}
	}

	return results, nil
}
