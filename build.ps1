# build.ps1 — builds the sensitive-data-scanner Go binary using a Docker container.
# No local Go installation required.
#
# Usage:
#   .\build.ps1                        # build all targets
#   .\build.ps1 -Target linux          # Linux amd64 only
#   .\build.ps1 -Target linux-arm64    # Linux arm64 only
#   .\build.ps1 -Target windows        # Windows amd64 only
#
# Output directory: build\

param(
  [ValidateSet("all", "linux", "linux-arm64", "windows")]
  [string]$Target = "all"
)

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir   = Join-Path $ScriptDir "build"
$SrcMount   = ($ScriptDir + "/src").Replace('\', '/')
$BuildMount = $BuildDir.Replace('\', '/')
$Image      = "golang:1.22-alpine"

if (-not (Test-Path $BuildDir)) {
  New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

function Invoke-Build([string]$GoOS, [string]$GoArch, [string]$Out) {
  Write-Host "  [${GoOS}/${GoArch}] Building..."
  docker run --rm `
    -v "${SrcMount}:/src:ro" `
    -v "${BuildMount}:/out" `
    -w /src `
    $Image `
    sh -c "CGO_ENABLED=0 GOOS=${GoOS} GOARCH=${GoArch} go build -ldflags='-s -w' -o /out/${Out} ."
  if ($LASTEXITCODE -ne 0) { throw "Build failed for ${GoOS}/${GoArch}." }
  Write-Host "  [${GoOS}/${GoArch}] -> build/${Out}"
}

Write-Host "=== sensitive-data-scanner build ==="

switch ($Target) {
  "linux"       { Invoke-Build linux   amd64 scanner-linux-amd64 }
  "linux-arm64" { Invoke-Build linux   arm64 scanner-linux-arm64 }
  "windows"     { Invoke-Build windows amd64 scanner-windows-amd64.exe }
  "all" {
    Invoke-Build linux   amd64 scanner-linux-amd64
    Invoke-Build linux   arm64 scanner-linux-arm64
    Invoke-Build windows amd64 scanner-windows-amd64.exe
  }
}

Write-Host ""
Write-Host "Done. Binaries are in: $BuildDir"
