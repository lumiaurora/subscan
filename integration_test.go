//go:build integration

package main

import (
	"os"
	"testing"
)

func TestLivePassiveEnumeration(t *testing.T) {
	if os.Getenv("SUBSCAN_RUN_LIVE_TESTS") != "1" {
		t.Skip("set SUBSCAN_RUN_LIVE_TESTS=1 to run live integration tests")
	}

	domain := os.Getenv("SUBSCAN_LIVE_DOMAIN")
	if domain == "" {
		domain = "cloudflare.com"
	}

	selectedSources, err := selectSources(sourceRegistry, []string{"certspotter", "rapiddns", "urlscan"}, nil)
	if err != nil {
		t.Fatalf("selectSources returned error: %v", err)
	}

	sourceResults, hadSuccess := querySources(domain, selectedSources, 3, true)
	if !hadSuccess {
		t.Fatalf("expected at least one live source to succeed for %s", domain)
	}

	rawResults, unique, attribution := aggregateSourceEntries(domain, sourceResults)
	if rawResults == 0 {
		t.Fatalf("expected raw results for %s", domain)
	}

	if len(unique) == 0 {
		t.Fatalf("expected unique subdomains for %s", domain)
	}

	if len(attribution) == 0 {
		t.Fatalf("expected source attribution data for %s", domain)
	}
}
