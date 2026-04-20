package main

import (
	"slices"
	"testing"
)

func TestSelectSourcesIncludeExclude(t *testing.T) {
	registry := []sourceDefinition{
		{id: "alpha", name: "Alpha", aliases: []string{"alpha"}},
		{id: "beta", name: "Beta", aliases: []string{"beta"}},
		{id: "gamma", name: "Gamma", aliases: []string{"gamma"}, enabled: func() bool { return false }, enableHint: "missing key"},
	}

	selected, err := selectSources(registry, []string{"alpha", "beta"}, []string{"beta"})
	if err != nil {
		t.Fatalf("selectSources returned error: %v", err)
	}

	if len(selected) != 1 || selected[0].id != "alpha" {
		t.Fatalf("expected only alpha to remain after exclusion")
	}

	if _, err := selectSources(registry, []string{"gamma"}, nil); err == nil {
		t.Fatalf("expected disabled source selection to fail")
	}
}

func TestParseCSVListDeduplicates(t *testing.T) {
	got := parseCSVList("crtsh, certspotter,crtsh,  urlscan ")
	want := []string{"crtsh", "certspotter", "urlscan"}

	if len(got) != len(want) {
		t.Fatalf("expected %d values, got %d", len(want), len(got))
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry %d: want %q, got %q", index, want[index], got[index])
		}
	}
}

func TestAggregateSourceEntriesTracksAttribution(t *testing.T) {
	results := []sourceResult{
		{
			source:  sourceDefinition{name: "crt.sh"},
			entries: []string{"WWW.example.com", "*.api.example.com", "invalid.org"},
		},
		{
			source:  sourceDefinition{name: "Cert Spotter"},
			entries: []string{"api.example.com", "mail.example.com", "mail.example.com"},
		},
		{
			source: sourceDefinition{name: "AlienVault OTX"},
			err:    errSentinel{},
		},
	}

	rawCount, unique, attribution := aggregateSourceEntries("example.com", results)
	if rawCount != 6 {
		t.Fatalf("expected raw count 6, got %d", rawCount)
	}

	wantUnique := []string{"api.example.com", "mail.example.com", "www.example.com"}
	if !slices.Equal(unique, wantUnique) {
		t.Fatalf("expected unique %v, got %v", wantUnique, unique)
	}

	if !slices.Equal(attribution["api.example.com"], []string{"Cert Spotter", "crt.sh"}) {
		t.Fatalf("unexpected attribution for api.example.com: %v", attribution["api.example.com"])
	}
}

type errSentinel struct{}

func (errSentinel) Error() string {
	return "boom"
}
