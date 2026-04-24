package main

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Finding is one detected secret instance.
type Finding struct {
	ID            int
	File          string
	Filename      string
	LineNumber    int
	SecretType    string
	RawValue      string
	RedactedValue string
}

// entropyConfig controls optional high-entropy string detection.
type entropyConfig struct {
	enabled   bool
	threshold float64 // bits per character; default 4.5
	minLen    int     // minimum token length; default 20
}

// defaultExcludedDirs mirrors the Node.js scanner's exclusion list.
var defaultExcludedDirs = map[string]bool{
	".git": true, "node_modules": true, ".cache": true, "dist": true,
	"build": true, "vendor": true, "__pycache__": true, ".yarn": true,
	".next": true, ".nuxt": true, "target": true, ".venv": true,
	"venv": true, ".tox": true, "coverage": true, ".nyc_output": true,
	".parcel-cache": true, ".turbo": true, ".svelte-kit": true,
	"out": true, ".output": true,
}

// isBinary returns true if the first 8 KB of data contains a null byte.
func isBinary(data []byte) bool {
	limit := len(data)
	if limit > 8192 {
		limit = 8192
	}
	return bytes.Contains(data[:limit], []byte{0})
}

// walkDirectory recursively collects file paths under rootDir.
// Directories listed in defaultExcludedDirs or extraExclude are skipped.
// When allowedExts is non-empty, only files whose extension or full name
// appears in the set are included.
func walkDirectory(rootDir string, extraExclude, allowedExts map[string]bool) ([]string, error) {
	var files []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries silently
		}
		if info.IsDir() {
			name := info.Name()
			if defaultExcludedDirs[name] || extraExclude[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(allowedExts) > 0 {
			ext := strings.ToLower(filepath.Ext(info.Name()))
			name := strings.ToLower(info.Name())
			if !allowedExts[ext] && !allowedExts[name] {
				return nil
			}
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

// scanFile reads a file and matches every compiled pattern against each line.
// When ent.enabled is true, high-entropy tokens are also reported as findings.
// Returns (findings, isBinaryFile, error).
func scanFile(path string, patterns []CompiledPattern, ent entropyConfig) ([]Finding, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if isBinary(data) {
		return nil, true, nil
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for lineIdx, line := range lines {
		var lineFindings []Finding

		// Pattern matching.
		for _, p := range patterns {
			var locs [][]int

			if p.CaptureGroup > 0 {
				all := p.Regex.FindAllStringSubmatchIndex(line, -1)
				for _, m := range all {
					cgStart := p.CaptureGroup * 2
					cgEnd := cgStart + 1
					if len(m) > cgEnd && m[cgStart] >= 0 && m[cgEnd] >= 0 {
						locs = append(locs, []int{m[cgStart], m[cgEnd]})
					}
				}
			} else {
				locs = p.Regex.FindAllStringIndex(line, -1)
			}

			for _, loc := range locs {
				raw := line[loc[0]:loc[1]]
				if raw == "" {
					continue
				}
				if p.Validator != "" && !validate(p.Validator, raw) {
					continue
				}
				lineFindings = append(lineFindings, Finding{
					File:          path,
					Filename:      filepath.Base(path),
					LineNumber:    lineIdx + 1,
					SecretType:    p.Name,
					RawValue:      raw,
					RedactedValue: redactValue(p.Name, raw),
				})
			}
		}

		// Entropy detection — only tokens not already caught by a pattern.
		if ent.enabled {
			alreadyFound := make(map[string]bool, len(lineFindings))
			for _, f := range lineFindings {
				alreadyFound[f.RawValue] = true
			}
			for _, token := range extractEntropyTokens(line, ent.minLen) {
				if overlapsFound(token, alreadyFound) {
					continue
				}
				if shannonEntropy(token) >= ent.threshold {
					lineFindings = append(lineFindings, Finding{
						File:          path,
						Filename:      filepath.Base(path),
						LineNumber:    lineIdx + 1,
						SecretType:    "High-Entropy String",
						RawValue:      token,
						RedactedValue: redactValue("High-Entropy String", token),
					})
				}
			}
		}

		findings = append(findings, lineFindings...)
	}
	return findings, false, nil
}

// overlapsFound returns true if token is a substring of, or contains, any
// value already reported by a pattern match on the same line.
func overlapsFound(token string, found map[string]bool) bool {
	for raw := range found {
		if strings.Contains(raw, token) || strings.Contains(token, raw) {
			return true
		}
	}
	return false
}

// extractEntropyTokens splits a line on common delimiters and returns tokens
// whose length >= minLen and whose characters are within the secret charset
// [A-Za-z0-9/+_\-=].
func extractEntropyTokens(line string, minLen int) []string {
	parts := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '=', ':', '"', '\'', ',', ';',
			'{', '}', '(', ')', '[', ']', '<', '>', '|', '&', '\\', '#':
			return true
		}
		return false
	})
	out := parts[:0]
	for _, p := range parts {
		if len(p) >= minLen && isSecretCharset(p) {
			out = append(out, p)
		}
	}
	return out
}

// isSecretCharset returns true if every character in s belongs to the
// typical secret charset: base64 alphanumeric plus /+_-=
func isSecretCharset(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '/' || r == '+' ||
			r == '_' || r == '-' || r == '=') {
			return false
		}
	}
	return true
}

// shannonEntropy computes the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, 64)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}
	n := float64(total)
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// validate runs a named post-match validator against a raw match value.
func validate(validator, s string) bool {
	switch validator {
	case "ssn":
		return isValidSSN(s)
	case "luhn":
		return isValidLuhn(s)
	}
	return true
}

// isValidSSN replicates the lookahead logic from the original JS pattern for
// SSNs, which RE2 cannot express natively. It rejects area 000, 666, 900-999
// and zero-value group or serial segments.
func isValidSSN(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	area, err := strconv.Atoi(parts[0])
	if err != nil || area == 0 || area == 666 || area >= 900 {
		return false
	}
	group, err := strconv.Atoi(parts[1])
	if err != nil || group == 0 {
		return false
	}
	serial, err := strconv.Atoi(parts[2])
	if err != nil || serial == 0 {
		return false
	}
	return true
}

// isValidLuhn verifies the Luhn check digit on a card number string.
// Non-digit characters are stripped before the check.
func isValidLuhn(s string) bool {
	var digits []int
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, int(ch-'0'))
		}
	}
	if len(digits) < 13 {
		return false
	}
	n := len(digits)
	sum := 0
	for i, d := range digits {
		// Double digits at even positions from the right (2nd, 4th, …).
		// Position from right is 1-indexed: n-i.
		if (n-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

var dbPasswordRe = regexp.MustCompile(`:[^:@\n]+@`)

// redactValue partially obscures a raw secret value for safe display.
func redactValue(secretType, rawValue string) string {
	switch secretType {
	case "Social Security Number (SSN)":
		if len(rawValue) >= 4 {
			return "***-**-" + rawValue[len(rawValue)-4:]
		}
		return "***-**-****"

	case "Credit Card Number":
		digits := regexp.MustCompile(`\D`).ReplaceAllString(rawValue, "")
		if len(digits) >= 4 {
			return "****-****-****-" + digits[len(digits)-4:]
		}
		return "****-****-****-****"

	case "Private Key (PEM header)":
		return "[PRIVATE KEY DETECTED — see full report]"

	case "Database Connection String":
		return dbPasswordRe.ReplaceAllString(rawValue, ":***@")

	default:
		if len(rawValue) <= 8 {
			return "****"
		}
		return rawValue[:4] + "****" + rawValue[len(rawValue)-4:]
	}
}
