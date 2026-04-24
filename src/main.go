package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type config struct {
	targetDir        string
	extFlag          string
	excludeFlag      string
	suffixFlag       string
	outFlag          string
	patternsFlag     string
	summary          bool
	entropy          bool
	entropyThreshold float64
	entropyMinLen    int
	threads          int
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: scanner [options] <target-directory>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  --ext .js,.env,...          Only scan files with these extensions (dot optional)")
	fmt.Fprintln(os.Stderr, "  --exclude dir1,dir2         Extra directories to exclude (comma-separated)")
	fmt.Fprintln(os.Stderr, "  --suffix <str>              Suffix appended to all output filenames (e.g. -win)")
	fmt.Fprintln(os.Stderr, "  --out <path>                Output directory (default: ./scan-output-<timestamp>)")
	fmt.Fprintln(os.Stderr, "  --patterns <path>           Path to patterns JSON file (default: patterns.json)")
	fmt.Fprintln(os.Stderr, "  --summary                   Print finding counts by type; skip writing output files")
	fmt.Fprintln(os.Stderr, "  --entropy                   Enable high-entropy string detection")
	fmt.Fprintln(os.Stderr, "  --entropy-threshold <float> Entropy threshold in bits/char (default 4.5)")
	fmt.Fprintln(os.Stderr, "  --entropy-min-len <int>     Minimum token length for entropy check (default 20)")
	fmt.Fprintln(os.Stderr, "  --threads <int>             Parallel scan workers (default 1)")
	fmt.Fprintln(os.Stderr, "  -h, --help                  Show this help")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Default excluded directories:")
	fmt.Fprintln(os.Stderr, "  .git, node_modules, .cache, dist, build, vendor, __pycache__, .yarn,")
	fmt.Fprintln(os.Stderr, "  .next, .nuxt, target, .venv, venv, .tox, coverage, .nyc_output,")
	fmt.Fprintln(os.Stderr, "  .parcel-cache, .turbo, .svelte-kit, out, .output")
}

// parseArgs is a flags-anywhere parser: flags and the positional target directory
// may appear in any order, matching the original Node.js CLI behaviour.
func parseArgs(argv []string) (config, error) {
	cfg := config{
		patternsFlag:     "patterns.json",
		entropyThreshold: 4.5,
		entropyMinLen:    20,
		threads:          1,
	}
	args := argv[1:]

	needsValue := map[string]bool{
		"ext": true, "exclude": true, "suffix": true, "out": true, "patterns": true,
		"threads": true, "entropy-threshold": true, "entropy-min-len": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			usage()
			os.Exit(0)
		}

		if strings.HasPrefix(arg, "-") {
			name := strings.TrimLeft(arg, "-")
			val := ""

			if idx := strings.IndexByte(name, '='); idx >= 0 {
				val = name[idx+1:]
				name = name[:idx]
			} else if needsValue[name] {
				if i+1 >= len(args) {
					return cfg, fmt.Errorf("flag --%s requires a value", name)
				}
				i++
				val = args[i]
			}

			switch name {
			case "ext":
				cfg.extFlag = val
			case "exclude":
				cfg.excludeFlag = val
			case "suffix":
				cfg.suffixFlag = val
			case "out":
				cfg.outFlag = val
			case "patterns":
				cfg.patternsFlag = val
			case "summary":
				cfg.summary = true
			case "entropy":
				cfg.entropy = true
			case "entropy-threshold":
				f, err := strconv.ParseFloat(val, 64)
				if err != nil || f <= 0 {
					return cfg, fmt.Errorf("--entropy-threshold must be a positive number")
				}
				cfg.entropyThreshold = f
				cfg.entropy = true
			case "entropy-min-len":
				n, err := strconv.Atoi(val)
				if err != nil || n < 1 {
					return cfg, fmt.Errorf("--entropy-min-len must be a positive integer")
				}
				cfg.entropyMinLen = n
				cfg.entropy = true
			case "threads":
				n, err := strconv.Atoi(val)
				if err != nil || n < 1 {
					return cfg, fmt.Errorf("--threads must be a positive integer")
				}
				cfg.threads = n
			default:
				return cfg, fmt.Errorf("unknown flag: %s", arg)
			}
			continue
		}

		if cfg.targetDir == "" {
			cfg.targetDir = arg
		} else {
			return cfg, fmt.Errorf("unexpected argument: %s", arg)
		}
	}

	if cfg.targetDir == "" {
		return cfg, fmt.Errorf("a target directory is required")
	}
	return cfg, nil
}

func main() {
	cfg, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		usage()
		os.Exit(1)
	}

	targetDir, err := filepath.Abs(cfg.targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving target path: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(targetDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: %q is not a directory\n", targetDir)
		os.Exit(1)
	}

	// Build extension allow-list (accepts both ".js" and "js" forms).
	allowedExts := make(map[string]bool)
	if cfg.extFlag != "" {
		for _, e := range strings.Split(cfg.extFlag, ",") {
			e = strings.TrimSpace(strings.ToLower(e))
			if e == "" {
				continue
			}
			allowedExts[e] = true
			if strings.HasPrefix(e, ".") {
				allowedExts[e[1:]] = true
			} else {
				allowedExts["."+e] = true
			}
		}
	}

	// Build extra directory exclusion set.
	extraExclude := make(map[string]bool)
	if cfg.excludeFlag != "" {
		for _, d := range strings.Split(cfg.excludeFlag, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				extraExclude[d] = true
			}
		}
	}

	patterns, err := loadPatterns(cfg.patternsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading patterns: %v\n", err)
		os.Exit(1)
	}

	ent := entropyConfig{
		enabled:   cfg.entropy,
		threshold: cfg.entropyThreshold,
		minLen:    cfg.entropyMinLen,
	}

	fmt.Println("Sensitive Data Scanner")
	fmt.Printf("Scanning : %s\n", targetDir)
	if len(allowedExts) > 0 {
		fmt.Printf("Extensions: %s\n", cfg.extFlag)
	}
	if cfg.entropy {
		fmt.Printf("Entropy  : enabled (threshold=%.1f, min-len=%d)\n", cfg.entropyThreshold, cfg.entropyMinLen)
	}
	if cfg.threads > 1 {
		fmt.Printf("Threads  : %d\n", cfg.threads)
	}
	fmt.Println()

	files, err := walkDirectory(targetDir, extraExclude, allowedExts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking directory: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Files found: %d\n", len(files))

	allFindings, skippedLines := scanFiles(files, patterns, ent, cfg.threads)

	fmt.Printf("Findings : %d\n", len(allFindings))
	fmt.Printf("Skipped  : %d (binary or unreadable)\n", len(skippedLines))
	fmt.Println()

	if cfg.summary {
		printSummary(targetDir, len(files), allFindings, skippedLines)
		return
	}

	scanDate := time.Now().UTC().Format(time.RFC3339)
	var outDir string
	if cfg.outFlag != "" {
		outDir, err = filepath.Abs(cfg.outFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving output path: %v\n", err)
			os.Exit(1)
		}
		if err := os.MkdirAll(outDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			os.Exit(1)
		}
	} else {
		cwd, _ := os.Getwd()
		outDir, scanDate, err = makeOutputDir(cwd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("Output   : %s\n\n", outDir)

	suffix := cfg.suffixFlag
	fullPath, err := writeFullReport(outDir, suffix, targetDir, scanDate, allFindings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing full report: %v\n", err)
		os.Exit(1)
	}
	redactedPath, err := writeRedactedReport(outDir, suffix, targetDir, scanDate, allFindings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing redacted report: %v\n", err)
		os.Exit(1)
	}
	htmlPath, err := writeHTMLReport(outDir, suffix, targetDir, scanDate, allFindings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
		os.Exit(1)
	}
	datasetPath, err := writeDataset(outDir, suffix, allFindings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing dataset: %v\n", err)
		os.Exit(1)
	}
	skippedPath, _ := writeSkippedLog(outDir, suffix, skippedLines)

	fmt.Printf("Full report (RESTRICTED) : %s\n", fullPath)
	fmt.Printf("Redacted report (text)   : %s\n", redactedPath)
	fmt.Printf("Redacted report (HTML)   : %s\n", htmlPath)
	fmt.Printf("Dataset (JSON)           : %s\n", datasetPath)
	if skippedPath != "" {
		fmt.Printf("Skipped log              : %s\n", skippedPath)
	}
	fmt.Println()
	fmt.Println("SECURITY NOTICE: The full report contains unredacted secrets.")
	fmt.Println("Do NOT share or commit it. chmod 600 has been applied on Linux/macOS.")
}

// printSummary prints a finding-count-by-type table to stdout without writing files.
func printSummary(targetDir string, fileCount int, findings []Finding, skipped []string) {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.SecretType]++
	}

	type row struct {
		name  string
		count int
	}
	rows := make([]row, 0, len(counts))
	for k, v := range counts {
		rows = append(rows, row{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})

	maxLen := len("Secret Type")
	for _, r := range rows {
		if len(r.name) > maxLen {
			maxLen = len(r.name)
		}
	}

	sep := strings.Repeat("─", maxLen+2) + "───────"
	fmt.Printf("%-*s   Count\n", maxLen, "Secret Type")
	fmt.Println(sep)
	for _, r := range rows {
		fmt.Printf("%-*s   %5d\n", maxLen, r.name, r.count)
	}
	fmt.Println(sep)
	fmt.Printf("%-*s   %5d\n", maxLen, "Total", len(findings))
}
