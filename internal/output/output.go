package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Report struct {
	Domain          string      `json:"domain"`
	Timestamp       time.Time   `json:"timestamp"`
	TotalFound      int         `json:"total_found"`
	ResolvedEnabled bool        `json:"resolved_enabled"`
	Metadata        RunMetadata `json:"metadata"`
	Subdomains      []Subdomain `json:"subdomains"`
}

type RunMetadata struct {
	StartedAt        time.Time         `json:"started_at"`
	CompletedAt      time.Time         `json:"completed_at"`
	DurationMS       int64             `json:"duration_ms"`
	RawResults       int               `json:"raw_results"`
	UniqueSubdomains int               `json:"unique_subdomains"`
	FinalSubdomains  int               `json:"final_subdomains"`
	WildcardFiltered int               `json:"wildcard_filtered,omitempty"`
	EnabledSources   []SourceReference `json:"enabled_sources"`
	FailedSources    []FailedSource    `json:"failed_sources,omitempty"`
	SourceTimings    []SourceTiming    `json:"source_timings"`
}

type SourceReference struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type FailedSource struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Health     string `json:"health"`
	Error      string `json:"error"`
	DurationMS int64  `json:"duration_ms"`
}

type SourceTiming struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Candidates int    `json:"candidates"`
	DurationMS int64  `json:"duration_ms"`
}

type Subdomain struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
	IPs     []string `json:"ips,omitempty"`
	CNAMEs  []string `json:"cnames,omitempty"`
}

func WriteTXT(path string, subdomains []string) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, subdomain := range subdomains {
		if _, err := writer.WriteString(subdomain + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func WriteJSON(path string, report Report) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}

	return os.MkdirAll(dir, 0o755)
}
