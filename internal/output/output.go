package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

type Report struct {
	Domain          string   `json:"domain"`
	TotalFound      int      `json:"total_found"`
	ResolvedEnabled bool     `json:"resolved_enabled"`
	Subdomains      []string `json:"subdomains"`
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
