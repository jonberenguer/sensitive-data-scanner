package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Pattern is one entry from patterns.json.
type Pattern struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Pattern         string `json:"pattern"`
	CaseInsensitive bool   `json:"caseInsensitive"`
	CaptureGroup    int    `json:"captureGroup"`
	Validator       string `json:"validator,omitempty"`
}

type patternFile struct {
	Version  string    `json:"version"`
	Patterns []Pattern `json:"patterns"`
}

// CompiledPattern pairs a Pattern with its compiled regexp.
type CompiledPattern struct {
	Pattern
	Regex *regexp.Regexp
}

// loadPatterns reads a patterns.json file, compiles each regex, and returns
// the compiled slice. Case-insensitive patterns get a (?i) prefix.
func loadPatterns(path string) ([]CompiledPattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading patterns file %q: %w", path, err)
	}

	var pf patternFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing patterns file: %w", err)
	}
	if len(pf.Patterns) == 0 {
		return nil, fmt.Errorf("patterns file contains no patterns")
	}

	compiled := make([]CompiledPattern, 0, len(pf.Patterns))
	for _, p := range pf.Patterns {
		src := p.Pattern
		if p.CaseInsensitive {
			src = "(?i)" + src
		}
		re, err := regexp.Compile(src)
		if err != nil {
			return nil, fmt.Errorf("compiling pattern %q (%s): %w", p.Name, p.ID, err)
		}
		compiled = append(compiled, CompiledPattern{Pattern: p, Regex: re})
	}
	return compiled, nil
}
