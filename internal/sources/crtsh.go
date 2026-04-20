package sources

import (
	"fmt"
	"net/url"
	"strings"
)

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
		var response []crtShEntry
		if err := fetchJSON(requestURL, &response); err != nil {
			lastErr = err
			continue
		}

		results := make([]string, 0, len(response))
		for _, entry := range response {
			for _, name := range strings.Split(entry.NameValue, "\n") {
				results = append(results, name)
			}
		}

		return results, nil
	}

	return nil, lastErr
}
