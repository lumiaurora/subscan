package sources

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var hackerTargetRequestConfig = requestConfig{
	RetryBaseDelay: 3 * time.Second,
}

func FetchHackerTarget(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))

	body, err := fetchTextWithOptions(requestURL, nil, hackerTargetRequestConfig)
	if err != nil {
		return nil, classifyHackerTargetError(err)
	}

	results, err := parseHackerTargetResponse(body)
	if err != nil {
		return nil, err
	}

	return results, nil
}

func parseHackerTargetResponse(body string) ([]string, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, nil
	}

	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "api count exceeded") {
		return nil, rateLimitedSourceError("HackerTarget API limit exceeded", errors.New(body))
	}

	if strings.HasPrefix(lowerBody, "error") {
		return nil, degradedSourceError("HackerTarget returned an error", errors.New(body))
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

func classifyHackerTargetError(err error) error {
	if ErrorHealth(err) != HealthDegraded {
		return err
	}

	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("HackerTarget is rate limiting requests", err)
	case IsStatusCode(err, 502), IsStatusCode(err, 503), IsStatusCode(err, 504):
		return degradedSourceError("HackerTarget is temporarily unavailable", err)
	default:
		return degradedSourceError("HackerTarget request failed", err)
	}
}
