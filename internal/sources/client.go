package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const userAgent = "subscan/1.0 (Passive subdomain enumeration CLI)"

const (
	maxBodyBytes = 5 << 20
)

var httpClient = &http.Client{
	Timeout: defaultTimeout,
}

func fetchJSON(requestURL string, target any) error {
	return fetchJSONWithHeaders(requestURL, nil, target)
}

func fetchJSONWithHeaders(requestURL string, headers map[string]string, target any) error {
	body, err := fetchBody(requestURL, headers, "application/json")
	if err != nil {
		return err
	}

	if len(body) == 0 {
		return nil
	}

	if err := json.Unmarshal(body, target); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}

func fetchText(requestURL string) (string, error) {
	return fetchTextWithHeaders(requestURL, nil)
}

func fetchTextWithHeaders(requestURL string, headers map[string]string) (string, error) {
	body, err := fetchBody(requestURL, headers, "text/plain, application/json;q=0.9, */*;q=0.8")
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func fetchBody(requestURL string, headers map[string]string, accept string) ([]byte, error) {
	var lastErr error
	options := currentOptions()

	for attempt := 0; attempt <= options.Retries; attempt++ {
		body, err, retryAfter := doRequest(requestURL, headers, accept, attempt)
		if err == nil {
			return body, nil
		}

		lastErr = err
		if attempt == options.Retries || !shouldRetry(err) {
			break
		}

		verbosef("Retrying %s in %s after error: %v", requestURL, retryAfter, err)
		time.Sleep(retryAfter)
	}

	return nil, lastErr
}

func doRequest(requestURL string, headers map[string]string, accept string, attempt int) ([]byte, error, time.Duration) {
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err, 0
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err, defaultRetryDelay(attempt)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err, defaultRetryDelay(attempt)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusNoContent:
		return nil, nil, 0
	default:
		return nil, &httpStatusError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       bodySnippet(body),
		}, retryDelay(attempt, resp.Header.Get("Retry-After"))
	}

	return body, nil, 0
}

type httpStatusError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *httpStatusError) Error() string {
	if e.Body == "" {
		return e.Status
	}

	return fmt.Sprintf("%s: %s", e.Status, e.Body)
}

func shouldRetry(err error) bool {
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == http.StatusTooManyRequests || statusErr.StatusCode >= http.StatusInternalServerError
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "timeout") || strings.Contains(message, "connection reset") || strings.Contains(message, "unexpected eof")
}

func IsStatusCode(err error, statusCode int) bool {
	var statusErr *httpStatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

func IsDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func retryDelay(attempt int, headerValue string) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(headerValue)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}

	if retryAt, err := http.ParseTime(headerValue); err == nil {
		if delay := time.Until(retryAt); delay > 0 {
			return delay
		}
	}

	return defaultRetryDelay(attempt)
}

func defaultRetryDelay(attempt int) time.Duration {
	return time.Duration(attempt+1) * 2 * time.Second
}

func bodySnippet(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 120 {
		text = text[:120]
	}

	return text
}
