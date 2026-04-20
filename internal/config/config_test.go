package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	content := []byte(`{
  "otx_api_key": "otx-key",
  "defaults": {
    "resolve": true,
    "threads": 8,
    "include_sources": ["crtsh", "rapiddns"]
  }
}`)

	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	file, loadedPath, err := Load(configPath, true)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if loadedPath != configPath {
		t.Fatalf("expected path %q, got %q", configPath, loadedPath)
	}

	if file.OTXAPIKey != "otx-key" {
		t.Fatalf("expected OTX API key to be loaded")
	}

	if file.Defaults.Resolve == nil || !*file.Defaults.Resolve {
		t.Fatalf("expected resolve default to be true")
	}

	if file.Defaults.Threads == nil || *file.Defaults.Threads != 8 {
		t.Fatalf("expected threads default to be 8")
	}

	if len(file.Defaults.IncludeSources) != 2 {
		t.Fatalf("expected include_sources to be loaded")
	}
}

func TestLoadMissingConfigWhenImplicit(t *testing.T) {
	tempDir := t.TempDir()
	missingPath := filepath.Join(tempDir, "missing.json")

	file, loadedPath, err := Load(missingPath, false)
	if err != nil {
		t.Fatalf("expected no error for implicit missing config, got %v", err)
	}

	if loadedPath != "" {
		t.Fatalf("expected empty loaded path, got %q", loadedPath)
	}

	if file.OTXAPIKey != "" || file.VTAPIKey != "" || file.ShodanAPIKey != "" {
		t.Fatalf("expected API keys to be empty for missing implicit config")
	}

	if file.Defaults.Output != "" || len(file.Defaults.IncludeSources) != 0 || len(file.Defaults.ExcludeSources) != 0 {
		t.Fatalf("expected defaults to remain empty for missing implicit config")
	}
}
