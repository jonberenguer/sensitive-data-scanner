# Prototype: Sensitive Data Scanner

## Problem
Sensitive credentials and PII (API keys, tokens, passwords, SSNs, credit cards) are frequently committed or stored in plain text on filesystems. Teams need a way to scan for these across platforms and produce reports suitable for both technical and management audiences.

## Approach
- Define a regex pattern library covering each secret type (API keys, bearer tokens, password fields, SSNs, credit card numbers, AWS/GCP/Azure key patterns)
- Walk a target directory recursively, reading each text file line by line
- On a match, record: absolute path, filename, line number, matched secret type, and raw matched value
- Output 1 — Full report: all fields including raw secret; chmod 600 on Linux/macOS
- Output 2 — Redacted report: replace middle chars of secret with `****`, safe to share
- Output 3 — Dataset: structured CSV with columns `path,filename,line_number,secret_type,redacted_value`
- Deliver as three scripts sharing the same pattern library: `scan.sh` (Linux/macOS), `scan.ps1` (Windows)

## Data / State
- Input: a directory path to scan (CLI argument)
- State: in-memory list of findings during the run; no database
- Output: three files written to a timestamped output directory

## Open Questions
- Should binary files be skipped silently or logged as skipped?
Response: logged as skipped
- What is the false-positive tolerance? (Strict patterns reduce noise but miss variants)
Response: Strict patterns, but if user is able to discover more patterns should be added to the list.
- Should the script accept an exclude list (e.g., `.git/`, `node_modules/`)?
Response: yes, including and cache like directories
- Does the Windows version need to match the Linux output format exactly for downstream tooling?
Response: No, just make sure the filename appends `-win` to it. 
