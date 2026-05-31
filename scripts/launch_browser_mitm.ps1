# Launch MITM-DomainFronting browser integration (Diagnostics or Stealth).
# Requires Xray mixed-in on 127.0.0.1:10808 before use.
param(
    [ValidateSet("Diagnostics", "Stealth")]
    [string]$Mode = "Diagnostics",
    [string]$Url = "https://example.com",
    [string]$Proxy = "socks5://127.0.0.1:10808",
    [string]$ProfileDir = "",
    [switch]$Headless
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

if ($Mode -eq "Stealth") {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Error "Python is required for Stealth mode (CloakBrowser). Install Python 3 and: pip install cloakbrowser"
    }
    $stealthScript = Join-Path $PSScriptRoot "browser_stealth.py"
    $pyArgs = @($stealthScript, "--url", $Url, "--proxy", $Proxy)
    if ($Headless) { $pyArgs += "--headless" }
    Write-Host "Stealth path: CloakBrowser (https://github.com/CloakHQ/CloakBrowser) via $Proxy"
    & python @pyArgs
    exit $LASTEXITCODE
}

$ChromeCandidates = @(
    "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
)
$Chrome = $null
foreach ($c in $ChromeCandidates) {
    if (Test-Path $c) { $Chrome = $c; break }
}
if (-not $Chrome) {
    Write-Error "No Chrome/Edge binary found. Install Chrome or use: python scripts\browser_diagnostics.py"
}

if (-not $ProfileDir) {
    $ProfileDir = Join-Path $env:TEMP "mitm-domainfronting-diagnostics-profile"
}
New-Item -ItemType Directory -Force -Path $ProfileDir | Out-Null

$ChromeArgs = @(
    "--user-data-dir=$ProfileDir",
    "--proxy-server=$Proxy",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-quic",
    "--disable-udp-proxies",
    "--disable-background-networking",
    "--disable-sync",
    "--ignore-certificate-errors",
    $Url
)
if ($Headless) {
    $ChromeArgs = @("--headless=new") + $ChromeArgs
}

Write-Host "Diagnostics path: $Chrome"
Write-Host "Proxy: $Proxy"
Write-Host "Profile: $ProfileDir"
& $Chrome @ChromeArgs
