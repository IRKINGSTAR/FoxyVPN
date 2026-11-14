package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// runTasklist lists running process names (lowercase, deduplicated).
func runTasklist() ([]string, error) {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tasklist failed: %w", err)
	}
	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, `"`) {
			continue
		}
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			continue
		}
		name := strings.ToLower(line[1 : 1+end])
		if name == "" || name == "system idle process" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}
