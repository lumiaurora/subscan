package utils

import "testing"

func TestNormalizeEntries(t *testing.T) {
	input := []string{"  WWW.Example.com  ", "*.api.example.com", "*.*.mail.example.com.", ""}
	got := NormalizeEntries(input)
	want := []string{"www.example.com", "api.example.com", "mail.example.com"}

	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(got))
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry %d: want %q, got %q", index, want[index], got[index])
		}
	}
}

func TestDeduplicatePreservesOrder(t *testing.T) {
	input := []string{"a.example.com", "b.example.com", "a.example.com", "", "b.example.com", "c.example.com"}
	got := Deduplicate(input)
	want := []string{"a.example.com", "b.example.com", "c.example.com"}

	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(got))
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry %d: want %q, got %q", index, want[index], got[index])
		}
	}
}
