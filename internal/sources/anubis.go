package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

var anubisRequestConfig = requestConfig{
	RetryBaseDelay: 3 * time.Second,
}

func FetchAnubis(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", url.PathEscape(domain))

	body, err := fetchBody(requestURL, nil, "application/json", anubisRequestConfig)
	if err != nil {
		return nil, classifyAnubisError(err)
	}

	results, err := parseAnubisResponse(body)
	if err != nil {
		return nil, degradedSourceError("Anubis returned invalid JSON", err)
	}

	return results, nil
}

func parseAnubisResponse(body []byte) ([]string, error) {
	var response []string
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	return response, nil
}

func classifyAnubisError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("Anubis is rate limiting requests", err)
	case IsStatusCode(err, 502), IsStatusCode(err, 503), IsStatusCode(err, 504):
		return degradedSourceError("Anubis is temporarily unavailable", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("Anubis returned malformed JSON", err)
		}

		return degradedSourceError("Anubis request failed", err)
	}
}
