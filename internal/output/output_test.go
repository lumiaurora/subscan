package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBatchTXT(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.txt")
	reports := []Report{
		{
			Domain: "example.com",
			Subdomains: []Subdomain{
				{Name: "api.example.com"},
				{Name: "www.example.com"},
			},
		},
		{
			Domain: "example.org",
			Subdomains: []Subdomain{
				{Name: "mail.example.org"},
			},
		},
	}

	if err := WriteBatchTXT(path, reports); err != nil {
		t.Fatalf("WriteBatchTXT returned error: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read batch TXT output: %v", err)
	}

	want := "example.com,api.example.com\nexample.com,www.example.com\nexample.org,mail.example.org\n"
	if string(body) != want {
		t.Fatalf("unexpected batch TXT output: %q", string(body))
	}
}
