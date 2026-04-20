package sources

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type bufferOverResponse struct {
	FDNSA  []string `json:"FDNS_A"`
	RDNS   []string `json:"RDNS"`
	Result []string `json:"Results"`
}

func FetchBufferOver(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://dns.bufferover.run/dns?q=%s", url.QueryEscape("."+domain))

	var response bufferOverResponse
	if err := fetchJSON(requestURL, &response); err != nil {
		if IsDNSNotFound(err) {
			return nil, errors.New("service endpoint dns.bufferover.run does not currently resolve")
		}

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

func parseBufferOverEntry(entry string) string {
	parts := strings.Split(entry, ",")
	if len(parts) == 0 {
		return ""
	}

	return strings.TrimSpace(parts[len(parts)-1])
}
