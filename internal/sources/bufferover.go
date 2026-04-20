package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var bufferOverRequestConfig = requestConfig{
	RetryBaseDelay: 3 * time.Second,
}

type bufferOverResponse struct {
	FDNSA  []string `json:"FDNS_A"`
	RDNS   []string `json:"RDNS"`
	Result []string `json:"Results"`
}

func FetchBufferOver(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://dns.bufferover.run/dns?q=%s", url.QueryEscape("."+domain))

	body, err := fetchBody(requestURL, nil, "application/json", bufferOverRequestConfig)
	if err != nil {
		if IsDNSNotFound(err) {
			return nil, degradedSourceError("BufferOver endpoint dns.bufferover.run does not currently resolve", err)
		}

		return nil, classifyBufferOverError(err)
	}

	results, err := parseBufferOverResponse(body)
	if err != nil {
		return nil, degradedSourceError("BufferOver returned invalid JSON", err)
	}

	return results, nil
}

func parseBufferOverResponse(body []byte) ([]string, error) {
	var response bufferOverResponse
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response.FDNSA)+len(response.RDNS)+len(response.Result))
	for _, entry := range response.FDNSA {
		if hostname := parseBufferOverEntry(entry); hostname != "" {
			results = append(results, hostname)
		}
	}

	for _, entry := range response.RDNS {
		if hostname := parseBufferOverEntry(entry); hostname != "" {
			results = append(results, hostname)
		}
	}

	for _, entry := range response.Result {
		if hostname := parseBufferOverEntry(entry); hostname != "" {
			results = append(results, hostname)
		}
	}

	return results, nil
}

func classifyBufferOverError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("BufferOver is rate limiting requests", err)
	case IsStatusCode(err, 502), IsStatusCode(err, 503), IsStatusCode(err, 504):
		return degradedSourceError("BufferOver is temporarily unavailable", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("BufferOver returned malformed JSON", err)
		}

		return degradedSourceError("BufferOver request failed", err)
	}
}

func parseBufferOverEntry(entry string) string {
	parts := strings.Split(entry, ",")
	if len(parts) == 0 {
		return ""
	}

	return strings.TrimSpace(parts[len(parts)-1])
}
