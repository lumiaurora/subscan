package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

var shodanRequestConfig = requestConfig{
	RetryBaseDelay: 5 * time.Second,
}

type shodanResponse struct {
	Subdomains []string `json:"subdomains"`
}

func FetchShodan(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", url.PathEscape(domain), url.QueryEscape(currentOptions().ShodanAPIKey))

	body, err := fetchBody(requestURL, nil, "application/json", shodanRequestConfig)
	if err != nil {
		return nil, classifyShodanError(err)
	}

	results, err := parseShodanResponse(domain, body)
	if err != nil {
		return nil, degradedSourceError("Shodan returned invalid JSON", err)
	}

	return results, nil
}

func parseShodanResponse(domain string, body []byte) ([]string, error) {
	var response shodanResponse
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response.Subdomains))
	for _, subdomain := range response.Subdomains {
		results = append(results, subdomain+"."+domain)
	}

	return results, nil
}

func classifyShodanError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("Shodan is rate limiting requests", err)
	case IsStatusCode(err, 401), IsStatusCode(err, 403):
		return authRequiredSourceError("Shodan rejected the configured API key", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("Shodan returned malformed JSON", err)
		}

		return degradedSourceError("Shodan request failed", err)
	}
}
