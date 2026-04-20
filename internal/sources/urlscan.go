package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

var urlscanRequestConfig = requestConfig{
	RetryBaseDelay: 4 * time.Second,
}

type urlscanResponse struct {
	Results []struct {
		Task struct {
			Domain string `json:"domain"`
		} `json:"task"`
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
	} `json:"results"`
}

func FetchURLScan(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", url.QueryEscape(domain))

	body, err := fetchBody(requestURL, nil, "application/json", urlscanRequestConfig)
	if err != nil {
		return nil, classifyURLScanError(err)
	}

	results, err := parseURLScanResponse(body)
	if err != nil {
		return nil, degradedSourceError("urlscan returned invalid JSON", err)
	}

	return results, nil
}

func parseURLScanResponse(body []byte) ([]string, error) {
	var response urlscanResponse
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response.Results)*2)
	for _, entry := range response.Results {
		results = append(results, entry.Task.Domain)
		results = append(results, entry.Page.Domain)
	}

	return results, nil
}

func classifyURLScanError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("urlscan is rate limiting requests", err)
	case IsStatusCode(err, 502), IsStatusCode(err, 503), IsStatusCode(err, 504):
		return degradedSourceError("urlscan is temporarily unavailable", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("urlscan returned malformed JSON", err)
		}

		return degradedSourceError("urlscan request failed", err)
	}
}
