[CmdletBinding()]
param(
    [string]$OutputDir = '.\artifacts\rm-case001-pcap-demo'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:SIFT_GUEST_PASSWORD)) {
    throw 'Set SIFT_GUEST_PASSWORD before running the demo.'
}

$cli = Join-Path $PSScriptRoot '..\.venv\Scripts\findevil-sift.exe'
if (-not (Test-Path -LiteralPath $cli)) {
    throw 'Install the project into .venv first: .\.venv\Scripts\python.exe -m pip install -e .'
}

& $cli pcap-triage `
    '/cases/R&M/case001-pcap/case001.pcap' `
    --output-dir $OutputDir

& $cli validate-pcap-summary `
    (Join-Path $OutputDir 'summary.json') `
    (Join-Path $PSScriptRoot '..\benchmarks\rm-case001-pcap.json') `
    --output (Join-Path $OutputDir 'validation.json')

