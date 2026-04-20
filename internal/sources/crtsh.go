package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var crtShRequestConfig = requestConfig{
	RetryBaseDelay: 3 * defaultRequestConfig.RetryBaseDelay / 2,
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func FetchCRTSh(domain string) ([]string, error) {
	requestURLs := []string{
		fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape("%."+domain)),
		fmt.Sprintf("https://crt.sh/?Identity=%s&output=json", url.QueryEscape("%."+domain)),
	}

	var lastErr error
	for _, requestURL := range requestURLs {
		body, err := fetchBody(requestURL, nil, "application/json", crtShRequestConfig)
		if err != nil {
			lastErr = classifyCRTShError(err)
			continue
		}

		results, err := parseCRTShResponse(body)
		if err != nil {
			lastErr = degradedSourceError("crt.sh returned invalid JSON", err)
			continue
		}

		return results, nil
	}

	return nil, lastErr
}

func parseCRTShResponse(body []byte) ([]string, error) {
	var response []crtShEntry
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response))
	for _, entry := range response {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			results = append(results, name)
		}
	}

	return results, nil
}

func classifyCRTShError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("crt.sh is rate limiting requests", err)
	case IsStatusCode(err, 502), IsStatusCode(err, 503), IsStatusCode(err, 504):
		return degradedSourceError("crt.sh is temporarily unavailable", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("crt.sh returned malformed JSON", err)
		}

		return degradedSourceError("crt.sh request failed", err)
	}
}
