'use strict';

const fs = require('fs');
const path = require('path');
const PATTERNS = require('./patterns');

const DEFAULT_EXCLUDES = new Set([
  '.git', 'node_modules', '.cache', 'dist', 'build', 'vendor',
  '__pycache__', '.yarn', '.next', '.nuxt', 'target', '.venv',
  'venv', '.tox', 'coverage', '.nyc_output', '.parcel-cache',
  '.turbo', '.svelte-kit', 'out', '.output',
]);

// Detects binary content by scanning the first 8KB for null bytes
function isBinary(buffer) {
  const limit = Math.min(buffer.length, 8192);
  for (let i = 0; i < limit; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

// Redacts a raw secret value according to its type
function redactValue(secretType, rawValue) {
  if (secretType === 'Social Security Number (SSN)') {
    return `***-**-${rawValue.slice(-4)}`;
  }
  if (secretType === 'Credit Card Number') {
    const digits = rawValue.replace(/\D/g, '');
    return `****-****-****-${digits.slice(-4)}`;
  }
  if (secretType === 'Private Key (PEM header)') {
    return '[PRIVATE KEY DETECTED — see full report]';
  }
  // Generic: expose first 4 and last 4 chars, obscure the middle
  if (rawValue.length <= 8) return '****';
  return `${rawValue.slice(0, 4)}****${rawValue.slice(-4)}`;
}

// Recursively walk a directory, returning file paths and skipped entries
function walkDirectory(rootDir, excludedDirs, allowedExtensions) {
  const files = [];
  const skipped = [];

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      console.error(`[WARN] Cannot read directory: ${dir}: ${err.message}`);
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (excludedDirs.has(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        if (allowedExtensions !== null) {
          const ext = path.extname(entry.name).toLowerCase();
          if (!allowedExtensions.has(ext) && !allowedExtensions.has(entry.name)) continue;
        }
        files.push(fullPath);
      }
    }
  }

  walk(rootDir);
  return { files, skipped };
}

// Scan a single file, returning findings and an optional skip reason
function scanFile(filePath) {
  let buffer;
  try {
    buffer = fs.readFileSync(filePath);
  } catch (err) {
    return { findings: [], skippedReason: `read error: ${err.message}` };
  }

  if (isBinary(buffer)) {
    return { findings: [], skippedReason: 'binary file' };
  }

  const content = buffer.toString('utf8');
  const lines = content.split('\n');
  const findings = [];

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(line)) !== null) {
        // Prefer capture group 1 (the isolated secret) when the pattern defines one
        const rawValue = match[1] !== undefined ? match[1] : match[0];
        if (!rawValue) continue;
        findings.push({
          file: filePath,
          filename: path.basename(filePath),
          lineNumber: lineIdx + 1,
          secretType: pattern.name,
          rawValue,
          redactedValue: redactValue(pattern.name, rawValue),
        });
      }
    }
  }

  return { findings, skippedReason: null };
}

// Formats a text banner header common to both report types
function reportHeader(title, scanDate, scanTarget, totalFindings, extraLines) {
  return [
    title,
    '='.repeat(72),
    `Scan Date    : ${scanDate}`,
    `Scan Target  : ${scanTarget}`,
    `Total Findings: ${totalFindings}`,
    ...extraLines,
    '='.repeat(72),
    '',
  ].join('\n');
}

function writeFullReport(outputDir, findings, scanTarget, scanDate, suffix) {
  const filePath = path.join(outputDir, `full-report${suffix}.txt`);
  const header = reportHeader(
    'Sensitive Data Scanner — FULL REPORT (CONFIDENTIAL)',
    scanDate, scanTarget, findings.length,
    [
      '',
      '!! WARNING: This file contains raw, unredacted secret values.       !!',
      '!! Do NOT share, email, or commit this file. chmod 600 is applied.  !!',
    ]
  );

  const body = findings.map((f, i) => [
    `[${i + 1}] File       : ${f.file}`,
    `    Line       : ${f.lineNumber}`,
    `    Secret Type: ${f.secretType}`,
    `    Raw Value  : ${f.rawValue}`,
    '',
  ].join('\n')).join('\n');

  fs.writeFileSync(filePath, header + '\n' + body, 'utf8');

  try {
    fs.chmodSync(filePath, 0o600);
  } catch (_) {
    // chmod is not supported on Windows; silently continue
  }

  return filePath;
}

function writeRedactedReport(outputDir, findings, scanTarget, scanDate, suffix) {
  const filePath = path.join(outputDir, `redacted-report${suffix}.txt`);
  const header = reportHeader(
    'Sensitive Data Scanner — Redacted Report (Management Summary)',
    scanDate, scanTarget, findings.length,
    ['Note: Secret values are partially redacted. Full values are in the restricted full report.']
  );

  const body = findings.map((f, i) => [
    `[${i + 1}] File       : ${f.file}`,
    `    Line       : ${f.lineNumber}`,
    `    Secret Type: ${f.secretType}`,
    `    Redacted   : ${f.redactedValue}`,
    '',
  ].join('\n')).join('\n');

  fs.writeFileSync(filePath, header + '\n' + body, 'utf8');
  return filePath;
}

function writeDataset(outputDir, findings, suffix) {
  const filePath = path.join(outputDir, `findings${suffix}.json`);
  const dataset = findings.map((f, i) => ({
    id: i + 1,
    file: f.file,
    filename: f.filename,
    lineNumber: f.lineNumber,
    secretType: f.secretType,
    redactedValue: f.redactedValue,
  }));
  fs.writeFileSync(filePath, JSON.stringify(dataset, null, 2), 'utf8');
  return filePath;
}

function writeSkippedLog(outputDir, skippedFiles, suffix) {
  if (skippedFiles.length === 0) return null;
  const filePath = path.join(outputDir, `skipped${suffix}.log`);
  const lines = skippedFiles.map(s => `[${s.reason}] ${s.file}`);
  fs.writeFileSync(filePath, lines.join('\n') + '\n', 'utf8');
  return filePath;
}

function parseArgs(argv) {
  const args = argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log([
      'Usage: node scanner.js <directory> [options]',
      '',
      'Options:',
      '  --ext .js,.env,...    Only scan files with these extensions (comma-separated)',
      '  --exclude dir1,dir2   Additional directories to exclude (comma-separated)',
      '  --suffix <str>        Append a suffix to all output filenames (e.g. -win)',
      '  --out <path>          Custom output directory (default: ./scan-output-<timestamp>)',
      '  -h, --help            Show this help',
      '',
      'Default excluded directories (in addition to --exclude):',
      '  .git, node_modules, .cache, dist, build, vendor, __pycache__, .yarn,',
      '  .next, .nuxt, target, .venv, venv, .tox, coverage, .nyc_output,',
      '  .parcel-cache, .turbo, .svelte-kit, out, .output',
    ].join('\n'));
    process.exit(0);
  }

  const config = {
    targetDir: null,
    extensions: null,   // null = all files
    excludedDirs: new Set(DEFAULT_EXCLUDES),
    platformSuffix: '',
    outputDir: null,
  };

  let i = 0;
  // First positional arg is the target directory
  if (args[0] && !args[0].startsWith('-')) {
    config.targetDir = path.resolve(args[0]);
    i = 1;
  }

  for (; i < args.length; i++) {
    const flag = args[i];
    switch (flag) {
      case '--ext':
        config.extensions = new Set(
          args[++i].split(',').map(e => e.trim().toLowerCase())
        );
        break;
      case '--exclude':
        for (const d of args[++i].split(',')) config.excludedDirs.add(d.trim());
        break;
      case '--suffix':
        config.platformSuffix = args[++i];
        break;
      case '--out':
        config.outputDir = path.resolve(args[++i]);
        break;
      default:
        if (!config.targetDir && !flag.startsWith('-')) {
          config.targetDir = path.resolve(flag);
        } else {
          console.error(`Unknown argument: ${flag}`);
          process.exit(1);
        }
    }
  }

  if (!config.targetDir) {
    console.error('Error: a target directory is required. Run with --help for usage.');
    process.exit(1);
  }

  return config;
}

function main() {
  const config = parseArgs(process.argv);

  if (!fs.existsSync(config.targetDir)) {
    console.error(`Error: directory does not exist: ${config.targetDir}`);
    process.exit(1);
  }
  if (!fs.statSync(config.targetDir).isDirectory()) {
    console.error(`Error: not a directory: ${config.targetDir}`);
    process.exit(1);
  }

  const scanDate = new Date().toISOString();
  const timestamp = scanDate.replace(/[:.]/g, '-').slice(0, 19);
  const outputDir = config.outputDir || path.join(process.cwd(), `scan-output-${timestamp}`);
  fs.mkdirSync(outputDir, { recursive: true });

  console.log('Sensitive Data Scanner');
  console.log(`Scanning : ${config.targetDir}`);
  console.log(`Output   : ${outputDir}`);
  if (config.extensions) console.log(`Extensions: ${[...config.extensions].join(', ')}`);
  console.log('');

  const { files } = walkDirectory(config.targetDir, config.excludedDirs, config.extensions);
  console.log(`Files found: ${files.length}`);

  const allFindings = [];
  const skippedFiles = [];

  for (const filePath of files) {
    const { findings, skippedReason } = scanFile(filePath);
    if (skippedReason) {
      skippedFiles.push({ file: filePath, reason: skippedReason });
    } else {
      allFindings.push(...findings);
    }
  }

  console.log(`Findings : ${allFindings.length}`);
  console.log(`Skipped  : ${skippedFiles.length} (binary or unreadable)`);
  console.log('');

  const s = config.platformSuffix;
  const fullPath     = writeFullReport(outputDir, allFindings, config.targetDir, scanDate, s);
  const redactedPath = writeRedactedReport(outputDir, allFindings, config.targetDir, scanDate, s);
  const datasetPath  = writeDataset(outputDir, allFindings, s);
  const skippedPath  = writeSkippedLog(outputDir, skippedFiles, s);

  console.log(`Full report (RESTRICTED) : ${fullPath}`);
  console.log(`Redacted report          : ${redactedPath}`);
  console.log(`Dataset (JSON)           : ${datasetPath}`);
  if (skippedPath) console.log(`Skipped log              : ${skippedPath}`);
  console.log('');
  console.log('SECURITY NOTICE: The full report contains unredacted secrets.');
  console.log('Do NOT share or commit it. chmod 600 has been applied on Linux/macOS.');
}

main();
