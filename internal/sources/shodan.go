package sources

import (
	"fmt"
	"net/url"
)

type shodanResponse struct {
	Subdomains []string `json:"subdomains"`
}

func FetchShodan(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", url.PathEscape(domain), url.QueryEscape(currentOptions().ShodanAPIKey))

	var response shodanResponse
	if err := fetchJSON(requestURL, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response.Subdomains))
	for _, subdomain := range response.Subdomains {
		results = append(results, subdomain+"."+domain)
	}

	return results, nil
}
