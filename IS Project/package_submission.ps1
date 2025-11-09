param(
    [string]$OutZip = "submission.zip"
)

$ErrorActionPreference = "Stop"

# Paths
$projectRoot = Split-Path -Parent $PSCommandPath
$dist = Join-Path $projectRoot "dist_submission"

# Clean dist
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Path $dist | Out-Null

# Files to include (essential for running the project)
$include = @(
    "firewall.py",
    "configuration_policy.py",
    "rule_engine.py",
    "stateful_inspection.py",
    "packet_capture.py",
    "rule_management.py",
    "logging_monitoring.py",
    "start_firewall.py",
    "start_firewall.bat",
    "firewall_config.json",
    "policies.json",
    "rules.json",
    "WinDivert.dll",
    "WinDivert64.sys",
    "requirements.txt",
    "README.md",
    "FIREWALL_GUIDE.md"
)

# Copy included files if they exist
foreach ($rel in $include) {
    $src = Join-Path $projectRoot $rel
    if (Test-Path $src) {
        Copy-Item $src -Destination (Join-Path $dist (Split-Path $rel -Leaf)) -Force
    }
}

# Optional: create a minimal README if none found
$readme = Join-Path $dist "README_submission.txt"
if (-not (Test-Path (Join-Path $dist "README.md"))) {
@"
How to run
==========
1) Install dependencies: pip install -r requirements.txt
2) Run: python start_firewall.py
3) The app uses WinDivert; ensure you run as Administrator on Windows.

Notes
-----
- Configuration and policies are in firewall_config.json and policies.json.
- Use the Configuration tab to live-apply changes without restart.
"@ | Set-Content -Path $readme -Encoding UTF8
}

# Create zip next to dist folder
$zipPath = Join-Path $projectRoot $OutZip
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zipPath

Write-Host "Submission package created: $zipPath" -ForegroundColor Green


