[CmdletBinding()]
param(
    [string]$OutputRoot = '.\artifacts\rm-case-demo'
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

& $cli run-case `
    (Join-Path $PSScriptRoot '..\cases\rm-stolen-szechuan-sauce.json') `
    --output-dir $OutputRoot `
    --max-attempts 2
