package sources

import (
	"fmt"
	"net/url"
	"regexp"
	"time"
)

var rapidDNSRequestConfig = requestConfig{
	RetryBaseDelay: 3 * time.Second,
}

func FetchRapidDNS(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", url.PathEscape(domain))

	body, err := fetchTextWithOptions(requestURL, nil, rapidDNSRequestConfig)
	if err != nil {
		return nil, classifyRapidDNSError(err)
	}

	results, err := parseRapidDNSResponse(domain, body)
	if err != nil {
		return nil, degradedSourceError("RapidDNS returned unexpected HTML", err)
	}

	return results, nil
}

func parseRapidDNSResponse(domain string, body string) ([]string, error) {
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

func classifyRapidDNSError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("RapidDNS is rate limiting requests", err)
	case IsStatusCode(err, 502), IsStatusCode(err, 503), IsStatusCode(err, 504):
		return degradedSourceError("RapidDNS is temporarily unavailable", err)
	default:
		return degradedSourceError("RapidDNS request failed", err)
	}
}
