package sources

import (
	"errors"
	"fmt"
	"net/url"
)

const maxOTXPages = 10

type otxResponse struct {
	HasNext    bool `json:"has_next"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func FetchOTX(domain string) ([]string, error) {
	baseURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))
	requestURL := baseURL
	results := make([]string, 0)
	headers := optionalOTXHeaders()

	for page := 1; page <= maxOTXPages; page++ {
		var response otxResponse
		if err := fetchJSONWithHeaders(requestURL, headers, &response); err != nil {
			if IsStatusCode(err, 429) && !OTXAPIKeyEnabled() {
				return nil, errors.New("429 Too Many Requests (set OTX_API_KEY to improve reliability)")
			}

			return nil, err
		}

		for _, record := range response.PassiveDNS {
			results = append(results, record.Hostname)
		}

		if !response.HasNext {
			break
		}

		requestURL = fmt.Sprintf("%s?page=%d", baseURL, page+1)
	}

	return results, nil
}
func optionalOTXHeaders() map[string]string {
	apiKey := currentOptions().OTXAPIKey
	if apiKey == "" {
		return nil
	}

	return map[string]string{"X-OTX-API-KEY": apiKey}
}
