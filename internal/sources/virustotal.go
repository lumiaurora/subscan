package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	maxVirusTotalPages = 5
)

var virusTotalRequestConfig = requestConfig{
	RetryBaseDelay: 5 * time.Second,
}

type virusTotalResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

func FetchVirusTotal(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", url.PathEscape(domain))
	results := make([]string, 0)
	headers := map[string]string{"x-apikey": currentOptions().VTAPIKey}

	for page := 0; page < maxVirusTotalPages; page++ {
		body, err := fetchBody(requestURL, headers, "application/json", virusTotalRequestConfig)
		if err != nil {
			return nil, classifyVirusTotalError(err)
		}

		pageResults, nextURL, err := parseVirusTotalResponse(body)
		if err != nil {
			return nil, degradedSourceError("VirusTotal returned invalid JSON", err)
		}

		results = append(results, pageResults...)

		if nextURL == "" {
			break
		}

		requestURL = nextURL
	}

	return results, nil
}

func parseVirusTotalResponse(body []byte) ([]string, string, error) {
	var response virusTotalResponse
	if err := decodeJSON(body, &response); err != nil {
		return nil, "", err
	}

	results := make([]string, 0, len(response.Data))
	for _, entry := range response.Data {
		results = append(results, entry.ID)
	}

	return results, response.Links.Next, nil
}

func classifyVirusTotalError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("VirusTotal is rate limiting requests", err)
	case IsStatusCode(err, 401), IsStatusCode(err, 403):
		return authRequiredSourceError("VirusTotal rejected the configured API key", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("VirusTotal returned malformed JSON", err)
		}

		return degradedSourceError("VirusTotal request failed", err)
	}
}
