package main

import "fmt"

type scanResult struct {
	idx      int
	findings []Finding
	skip     string // non-empty when the file was skipped; used as the log line
}

// scanFiles scans the given file list using a pool of numWorkers goroutines.
// When numWorkers <= 1 it runs sequentially.
// Results are returned in the same order as the input slice; IDs are assigned
// in that order so output is deterministic regardless of execution order.
func scanFiles(files []string, patterns []CompiledPattern, ent entropyConfig, numWorkers int) ([]Finding, []string) {
	if len(files) == 0 {
		return nil, nil
	}
	if numWorkers <= 1 {
		return runSeq(files, patterns, ent)
	}
	return runParallel(files, patterns, ent, numWorkers)
}

func runSeq(files []string, patterns []CompiledPattern, ent entropyConfig) ([]Finding, []string) {
	results := make([]scanResult, len(files))
	for i, f := range files {
		results[i] = process(i, f, patterns, ent)
	}
	return assemble(results)
}

func runParallel(files []string, patterns []CompiledPattern, ent entropyConfig, numWorkers int) ([]Finding, []string) {
	type work struct {
		idx  int
		path string
	}

	workCh := make(chan work, len(files))
	resultCh := make(chan scanResult, len(files))

	// Start workers.
	for i := 0; i < numWorkers; i++ {
		go func() {
			for w := range workCh {
				resultCh <- process(w.idx, w.path, patterns, ent)
			}
		}()
	}

	// Feed all work, then signal done.
	for i, f := range files {
		workCh <- work{i, f}
	}
	close(workCh)

	// Collect results into an ordered slice.
	results := make([]scanResult, len(files))
	for range files {
		r := <-resultCh
		results[r.idx] = r
	}

	return assemble(results)
}

// process runs scanFile for one file and returns a labelled result.
func process(idx int, path string, patterns []CompiledPattern, ent entropyConfig) scanResult {
	findings, binary, err := scanFile(path, patterns, ent)
	switch {
	case err != nil:
		return scanResult{idx, nil, fmt.Sprintf("[read error: %v] %s", err, path)}
	case binary:
		return scanResult{idx, nil, fmt.Sprintf("[binary file] %s", path)}
	default:
		return scanResult{idx, findings, ""}
	}
}

// assemble merges ordered results into findings (with sequential IDs) and a
// skipped-file log slice.
func assemble(results []scanResult) ([]Finding, []string) {
	var allFindings []Finding
	var skipped []string
	nextID := 1

	for _, r := range results {
		if r.skip != "" {
			skipped = append(skipped, r.skip)
			continue
		}
		for i := range r.findings {
			r.findings[i].ID = nextID
			nextID++
		}
		allFindings = append(allFindings, r.findings...)
	}
	return allFindings, skipped
}
