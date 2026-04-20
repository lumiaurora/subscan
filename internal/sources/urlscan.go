package sources

import (
	"fmt"
	"net/url"
)

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

	var response urlscanResponse
	if err := fetchJSON(requestURL, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response.Results)*2)
	for _, entry := range response.Results {
		results = append(results, entry.Task.Domain)
		results = append(results, entry.Page.Domain)
	}

	return results, nil
}
