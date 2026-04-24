# scan.ps1 — Windows wrapper for the sensitive data scanner (Go binary)
# Output filenames are suffixed with -win to distinguish from Linux/macOS runs.
#
# Usage:
#   .\scan.ps1 <TargetDir> [-Ext ".js,.env"] [-Exclude "dir1,dir2"] [-Out "C:\output"]

param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$TargetDir,

  [string]$Ext     = "",
  [string]$Exclude = "",
  [string]$Out     = ""
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Binary    = Join-Path $ScriptDir "build\scanner-windows-amd64.exe"
$Patterns  = Join-Path $ScriptDir "patterns.json"

if (-not (Test-Path $Binary)) {
  Write-Error "Scanner binary not found at $Binary. Run '.\build.ps1' (or '.\build.ps1 -Target windows') first."
  exit 1
}

# Always append -win suffix so Windows output files are distinct from Linux/macOS runs.
$ScanArgs = @($TargetDir, "--patterns", $Patterns, "--suffix", "-win")
if ($Ext)     { $ScanArgs += @("--ext",     $Ext) }
if ($Exclude) { $ScanArgs += @("--exclude", $Exclude) }
if ($Out)     { $ScanArgs += @("--out",     $Out) }

& $Binary @ScanArgs
exit $LASTEXITCODE
