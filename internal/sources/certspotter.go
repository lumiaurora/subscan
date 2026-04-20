package sources

import (
	"fmt"
	"net/url"
)

type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

func FetchCertSpotter(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", url.QueryEscape(domain))

	var response []certSpotterEntry
	if err := fetchJSON(requestURL, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response))
	for _, entry := range response {
		results = append(results, entry.DNSNames...)
	}

	return results, nil
}
