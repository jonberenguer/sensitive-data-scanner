package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// datasetEntry is the JSON-safe representation of a finding (no raw value).
type datasetEntry struct {
	ID            int    `json:"id"`
	File          string `json:"file"`
	Filename      string `json:"filename"`
	LineNumber    int    `json:"lineNumber"`
	SecretType    string `json:"secretType"`
	RedactedValue string `json:"redactedValue"`
}

func reportHeader(title, scanDate, scanTarget string, totalFindings int, extra []string) string {
	sep := strings.Repeat("=", 72)
	lines := []string{
		title,
		sep,
		fmt.Sprintf("Scan Date    : %s", scanDate),
		fmt.Sprintf("Scan Target  : %s", scanTarget),
		fmt.Sprintf("Total Findings: %d", totalFindings),
	}
	lines = append(lines, extra...)
	lines = append(lines, sep, "")
	return strings.Join(lines, "\n")
}

// writeFullReport writes all findings with raw secret values to a restricted file.
// chmod 600 is applied on non-Windows systems.
func writeFullReport(dir, suffix, scanTarget, scanDate string, findings []Finding) (string, error) {
	path := filepath.Join(dir, fmt.Sprintf("full-report%s.txt", suffix))
	header := reportHeader(
		"Sensitive Data Scanner — FULL REPORT (CONFIDENTIAL)",
		scanDate, scanTarget, len(findings),
		[]string{
			"",
			"!! WARNING: This file contains raw, unredacted secret values.       !!",
			"!! Do NOT share, email, or commit this file. chmod 600 is applied.  !!",
		},
	)

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n")
	for i, f := range findings {
		fmt.Fprintf(&sb, "[%d] File       : %s\n", i+1, f.File)
		fmt.Fprintf(&sb, "    Line       : %d\n", f.LineNumber)
		fmt.Fprintf(&sb, "    Secret Type: %s\n", f.SecretType)
		fmt.Fprintf(&sb, "    Raw Value  : %s\n\n", f.RawValue)
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0600)
	}
	return path, nil
}

// writeRedactedReport writes findings with redacted values, safe for management review.
func writeRedactedReport(dir, suffix, scanTarget, scanDate string, findings []Finding) (string, error) {
	path := filepath.Join(dir, fmt.Sprintf("redacted-report%s.txt", suffix))
	header := reportHeader(
		"Sensitive Data Scanner — Redacted Report (Management Summary)",
		scanDate, scanTarget, len(findings),
		[]string{"Note: Secret values are partially redacted. Full values are in the restricted full report."},
	)

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n")
	for i, f := range findings {
		fmt.Fprintf(&sb, "[%d] File       : %s\n", i+1, f.File)
		fmt.Fprintf(&sb, "    Line       : %d\n", f.LineNumber)
		fmt.Fprintf(&sb, "    Secret Type: %s\n", f.SecretType)
		fmt.Fprintf(&sb, "    Redacted   : %s\n\n", f.RedactedValue)
	}

	return path, os.WriteFile(path, []byte(sb.String()), 0644)
}

// writeDataset writes a JSON array of findings without raw secret values.
func writeDataset(dir, suffix string, findings []Finding) (string, error) {
	path := filepath.Join(dir, fmt.Sprintf("findings%s.json", suffix))
	entries := make([]datasetEntry, len(findings))
	for i, f := range findings {
		entries[i] = datasetEntry{
			ID:            f.ID,
			File:          f.File,
			Filename:      f.Filename,
			LineNumber:    f.LineNumber,
			SecretType:    f.SecretType,
			RedactedValue: f.RedactedValue,
		}
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0644)
}

// writeSkippedLog records binary or unreadable files. Returns "" if nothing to write.
func writeSkippedLog(dir, suffix string, skipped []string) (string, error) {
	if len(skipped) == 0 {
		return "", nil
	}
	path := filepath.Join(dir, fmt.Sprintf("skipped%s.log", suffix))
	return path, os.WriteFile(path, []byte(strings.Join(skipped, "\n")+"\n"), 0644)
}

// makeOutputDir creates and returns a timestamped output directory.
// If base is empty the current working directory is used.
func makeOutputDir(base string) (string, string, error) {
	ts := time.Now().Format("2006-01-02T15-04-05")
	scanDate := time.Now().UTC().Format(time.RFC3339)
	dir := filepath.Join(base, "scan-output-"+ts)
	return dir, scanDate, os.MkdirAll(dir, 0755)
}
