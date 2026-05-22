[CmdletBinding()]
param(
    [string]$OutputRoot = '.\artifacts\rm-two-lane-demo'
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

$pcapOutput = Join-Path $OutputRoot 'pcap'
$diskOutput = Join-Path $OutputRoot 'dc-disk'

& $cli pcap-triage `
    '/cases/R&M/case001-pcap/case001.pcap' `
    --output-dir $pcapOutput

& $cli validate-pcap-summary `
    (Join-Path $pcapOutput 'summary.json') `
    (Join-Path $PSScriptRoot '..\benchmarks\rm-case001-pcap.json') `
    --output (Join-Path $pcapOutput 'validation.json')

& $cli disk-triage `
    '/cases/R&M/DC/Combined/image.E01' `
    --output-dir $diskOutput

& $cli validate-disk-summary `
    (Join-Path $diskOutput 'summary.json') `
    (Join-Path $PSScriptRoot '..\benchmarks\rm-dc-disk.json') `
    --output (Join-Path $diskOutput 'validation.json')

