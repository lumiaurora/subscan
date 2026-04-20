package utils

import "testing"

func TestFilterSubdomains(t *testing.T) {
	input := []string{
		"example.com",
		"api.example.com",
		"deep.api.example.com",
		"otherexample.com",
		"badexample.com",
		"example.org",
	}

	got := FilterSubdomains(input, "example.com")
	want := []string{"api.example.com", "deep.api.example.com"}

	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(got))
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry %d: want %q, got %q", index, want[index], got[index])
		}
	}
}
