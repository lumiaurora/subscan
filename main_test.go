package main

import (
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
