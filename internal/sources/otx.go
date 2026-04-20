package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const maxOTXPages = 10

var otxRequestConfig = requestConfig{
	RetryBaseDelay: 4 * time.Second,
}

type otxResponse struct {
	HasNext    bool `json:"has_next"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func FetchOTX(domain string) ([]string, error) {
	baseURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))
	requestURL := baseURL
	results := make([]string, 0)
	headers := optionalOTXHeaders()

	for page := 1; page <= maxOTXPages; page++ {
		body, err := fetchBody(requestURL, headers, "application/json", otxRequestConfig)
		if err != nil {
			return nil, classifyOTXError(err)
		}

		pageResults, hasNext, err := parseOTXResponse(body)
		if err != nil {
			return nil, degradedSourceError("AlienVault OTX returned invalid JSON", err)
		}

		results = append(results, pageResults...)

		if !hasNext {
			break
		}

		requestURL = fmt.Sprintf("%s?page=%d", baseURL, page+1)
	}

	return results, nil
}

func parseOTXResponse(body []byte) ([]string, bool, error) {
	var response otxResponse
	if err := decodeJSON(body, &response); err != nil {
		return nil, false, err
	}

	results := make([]string, 0, len(response.PassiveDNS))
	for _, record := range response.PassiveDNS {
		results = append(results, record.Hostname)
	}

	return results, response.HasNext, nil
}

func classifyOTXError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		if !OTXAPIKeyEnabled() {
			return rateLimitedSourceError("AlienVault OTX is rate limiting anonymous requests; set OTX_API_KEY to improve reliability", err)
		}

		return rateLimitedSourceError("AlienVault OTX is rate limiting requests", err)
	case IsStatusCode(err, 401), IsStatusCode(err, 403):
		return authRequiredSourceError("AlienVault OTX rejected the configured API key", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("AlienVault OTX returned malformed JSON", err)
		}

		return degradedSourceError("AlienVault OTX request failed", err)
	}
}

func optionalOTXHeaders() map[string]string {
	apiKey := currentOptions().OTXAPIKey
	if apiKey == "" {
		return nil
	}

	return map[string]string{"X-OTX-API-KEY": apiKey}
}
