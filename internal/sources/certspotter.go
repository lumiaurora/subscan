package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

var certSpotterRequestConfig = requestConfig{
	RetryBaseDelay: 3 * time.Second,
}

type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

func FetchCertSpotter(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", url.QueryEscape(domain))

	body, err := fetchBody(requestURL, nil, "application/json", certSpotterRequestConfig)
	if err != nil {
		return nil, classifyCertSpotterError(err)
	}

	results, err := parseCertSpotterResponse(body)
	if err != nil {
		return nil, degradedSourceError("Cert Spotter returned invalid JSON", err)
	}

	return results, nil
}

func parseCertSpotterResponse(body []byte) ([]string, error) {
	var response []certSpotterEntry
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response))
	for _, entry := range response {
		results = append(results, entry.DNSNames...)
	}

	return results, nil
}

func classifyCertSpotterError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("Cert Spotter is rate limiting requests", err)
	case IsStatusCode(err, 502), IsStatusCode(err, 503), IsStatusCode(err, 504):
		return degradedSourceError("Cert Spotter is temporarily unavailable", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("Cert Spotter returned malformed JSON", err)
		}

		return degradedSourceError("Cert Spotter request failed", err)
	}
}
