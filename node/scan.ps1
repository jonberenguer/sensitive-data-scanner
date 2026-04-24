# scan.ps1 — Windows wrapper for the sensitive data scanner
# Output filenames are suffixed with -win to distinguish from Linux/macOS runs.
#
# Usage:
#   .\scan.ps1 <TargetDir> [-Ext ".js,.env"] [-Exclude "dir1,dir2"] [-Out "C:\output"]

param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$TargetDir,

  [string]$Ext = "",
  [string]$Exclude = "",
  [string]$Out = ""
)

$NodeExe = "node"
if (-not (Get-Command $NodeExe -ErrorAction SilentlyContinue)) {
  Write-Error "Node.js not found. Install it from https://nodejs.org, then re-run."
  exit 1
}

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScannerPath = Join-Path $ScriptDir "scanner.js"

# Build argument list; always append -win suffix so Windows output files are distinct
$NodeArgs = @($ScannerPath, $TargetDir, "--suffix", "-win")
if ($Ext)     { $NodeArgs += @("--ext",     $Ext) }
if ($Exclude) { $NodeArgs += @("--exclude", $Exclude) }
if ($Out)     { $NodeArgs += @("--out",     $Out) }

& $NodeExe @NodeArgs
exit $LASTEXITCODE
