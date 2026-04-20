package sources

import (
	"fmt"
	"net/url"
)

const (
	maxVirusTotalPages = 5
)

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
		var response virusTotalResponse
		if err := fetchJSONWithHeaders(requestURL, headers, &response); err != nil {
			return nil, err
		}

		for _, entry := range response.Data {
			results = append(results, entry.ID)
		}

		if response.Links.Next == "" {
			break
		}

		requestURL = response.Links.Next
	}

	return results, nil
}
