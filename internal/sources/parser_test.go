package sources

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseCRTShResponse(t *testing.T) {
	body := fixtureBytes(t, "crtsh.json")
	got, err := parseCRTShResponse(body)
	if err != nil {
		t.Fatalf("parseCRTShResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "api.example.com", "*.mail.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseOTXResponse(t *testing.T) {
	body := fixtureBytes(t, "otx.json")
	got, hasNext, err := parseOTXResponse(body)
	if err != nil {
		t.Fatalf("parseOTXResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "mail.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}

	if !hasNext {
		t.Fatalf("expected hasNext to be true")
	}
}

func TestParseBufferOverResponse(t *testing.T) {
	body := fixtureBytes(t, "bufferover.json")
	got, err := parseBufferOverResponse(body)
	if err != nil {
		t.Fatalf("parseBufferOverResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "mail.example.com", "mx.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseCertSpotterResponse(t *testing.T) {
	body := fixtureBytes(t, "certspotter.json")
	got, err := parseCertSpotterResponse(body)
	if err != nil {
		t.Fatalf("parseCertSpotterResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "api.example.com", "mail.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseHackerTargetResponse(t *testing.T) {
	body := string(fixtureBytes(t, "hackertarget.txt"))
	got, err := parseHackerTargetResponse(body)
	if err != nil {
		t.Fatalf("parseHackerTargetResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "api.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseAnubisResponse(t *testing.T) {
	body := fixtureBytes(t, "anubis.json")
	got, err := parseAnubisResponse(body)
	if err != nil {
		t.Fatalf("parseAnubisResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "mail.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseURLScanResponse(t *testing.T) {
	body := fixtureBytes(t, "urlscan.json")
	got, err := parseURLScanResponse(body)
	if err != nil {
		t.Fatalf("parseURLScanResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "app.example.com", "blog.example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseRapidDNSResponse(t *testing.T) {
	body := string(fixtureBytes(t, "rapiddns.html"))
	got, err := parseRapidDNSResponse("example.com", body)
	if err != nil {
		t.Fatalf("parseRapidDNSResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "*.api.example.com", "mail.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseVirusTotalResponse(t *testing.T) {
	body := fixtureBytes(t, "virustotal.json")
	got, nextURL, err := parseVirusTotalResponse(body)
	if err != nil {
		t.Fatalf("parseVirusTotalResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "api.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}

	if nextURL != "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=next" {
		t.Fatalf("unexpected next URL %q", nextURL)
	}
}

func TestParseShodanResponse(t *testing.T) {
	body := fixtureBytes(t, "shodan.json")
	got, err := parseShodanResponse("example.com", body)
	if err != nil {
		t.Fatalf("parseShodanResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "api.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestSourceHealthClassification(t *testing.T) {
	if health := ErrorHealth(classifyVirusTotalError(&httpStatusError{StatusCode: 401, Status: "401 Unauthorized"})); health != HealthAuthRequired {
		t.Fatalf("expected auth-required health, got %s", health)
	}

	if health := ErrorHealth(classifyOTXError(&httpStatusError{StatusCode: 429, Status: "429 Too Many Requests"})); health != HealthRateLimited {
		t.Fatalf("expected rate-limited health, got %s", health)
	}

	if health := ErrorHealth(classifyRapidDNSError(&httpStatusError{StatusCode: 503, Status: "503 Service Unavailable"})); health != HealthDegraded {
		t.Fatalf("expected degraded health, got %s", health)
	}

	if _, err := parseHackerTargetResponse("error api count exceeded"); ErrorHealth(err) != HealthRateLimited {
		t.Fatalf("expected HackerTarget parser to classify rate limiting")
	}
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}

	return body
}
