package sources

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func FetchHackerTarget(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))

	body, err := fetchText(requestURL)
	if err != nil {
		return nil, err
	}

	body = strings.TrimSpace(body)
	if body == "" {
		return nil, nil
	}

	if strings.HasPrefix(strings.ToLower(body), "error") || strings.Contains(strings.ToLower(body), "api count exceeded") {
		return nil, errors.New(body)
	}

	results := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		hostname, _, found := strings.Cut(line, ",")
		if found && hostname != "" {
			results = append(results, hostname)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}
