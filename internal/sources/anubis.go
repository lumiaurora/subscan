package sources

import (
	"fmt"
	"net/url"
)

func FetchAnubis(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", url.PathEscape(domain))

	var response []string
	if err := fetchJSON(requestURL, &response); err != nil {
		return nil, err
	}

	return response, nil
}
