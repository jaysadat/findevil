[CmdletBinding()]
param(
    [string]$OutputRoot = '.\artifacts\rm-live-demo',
    [string]$GuestCaseRoot = '/cases/R&M',
    [switch]$QuickCorrection,
    [switch]$CorrectionOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:SIFT_GUEST_PASSWORD)) {
    throw 'Set SIFT_GUEST_PASSWORD before running the live demo.'
}

$cli = Join-Path $PSScriptRoot '..\.venv\Scripts\findevil-sift.exe'
if (-not (Test-Path -LiteralPath $cli)) {
    throw 'Install the project into .venv first: .\.venv\Scripts\python.exe -m pip install -e .'
}

if (Test-Path -LiteralPath $OutputRoot) {
    throw "Live demo output root already exists: $OutputRoot"
}

$discoveryOutput = Join-Path $OutputRoot 'discovery'
$draftPlan = Join-Path $discoveryOutput 'rm-discovered.json'
$correctionPlan = $draftPlan
$correctionOutput = Join-Path $OutputRoot 'correction-run'
$fullCaseOutput = Join-Path $OutputRoot 'full-case'
$samplePlan = Join-Path $PSScriptRoot '..\cases\rm-stolen-szechuan-sauce.json'

function Invoke-FindEvil {
    param([string[]]$Arguments)

    & $cli @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "findevil-sift exited with code $LASTEXITCODE while running: $($Arguments -join ' ')"
    }
}

Invoke-FindEvil @(
    'discover-case',
    $GuestCaseRoot,
    '--output-dir', $discoveryOutput,
    '--plan-output', $draftPlan,
    '--case-id', 'rm-live-discovered',
    '--case-name', 'R&M Live Discovered Case'
)

if ($QuickCorrection) {
    $draft = Get-Content -Raw -LiteralPath $draftPlan | ConvertFrom-Json
    if (-not ($draft.lanes.PSObject.Properties.Name -contains 'memory')) {
        throw 'Discovered plan did not contain a memory lane for the quick correction path.'
    }

    $quickPlan = [ordered]@{
        case_id = 'rm-live-memory-review'
        case_name = 'R&M Live Memory Review'
        description = 'Quick recording plan derived from discovered real case memory evidence.'
        lanes = [ordered]@{
            memory = $draft.lanes.memory
        }
    }
    $correctionPlan = Join-Path $discoveryOutput 'rm-memory-review.json'
    $quickPlan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $correctionPlan -Encoding utf8
}

Invoke-FindEvil @(
    'run-case',
    $correctionPlan,
    '--output-dir', $correctionOutput,
    '--max-attempts', '2'
)

if (-not $CorrectionOnly) {
    Invoke-FindEvil @(
        'run-case',
        $samplePlan,
        '--output-dir', $fullCaseOutput,
        '--max-attempts', '2'
    )
}

$correctionLogPath = Join-Path $correctionOutput 'execution-log.json'
$correctionLog = Get-Content -Raw -LiteralPath $correctionLogPath | ConvertFrom-Json
$memoryAdjustment = @(
    $correctionLog.events |
        Where-Object {
            $_.event -eq 'lane_adjusted' -and
                $_.details.PSObject.Properties.Name -contains 'lane' -and
                $_.details.lane -eq 'memory'
        }
)
if ($memoryAdjustment.Count -eq 0) {
    throw 'Correction run did not record the expected memory lane adjustment.'
}

$manifest = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    guest_case_root = $GuestCaseRoot
    draft_plan = $draftPlan
    correction_plan = $correctionPlan
    quick_correction = [bool]$QuickCorrection
    correction_only = [bool]$CorrectionOnly
    correction_run = [ordered]@{
        status = $correctionLog.status
        execution_log = $correctionLogPath
        execution_report = (Join-Path $correctionOutput 'execution-report.md')
        correction_event = $memoryAdjustment[0]
    }
}
if (-not $CorrectionOnly) {
    $fullCaseLogPath = Join-Path $fullCaseOutput 'execution-log.json'
    $fullCaseLog = Get-Content -Raw -LiteralPath $fullCaseLogPath | ConvertFrom-Json
    $manifest['full_case'] = [ordered]@{
        status = $fullCaseLog.status
        execution_log = $fullCaseLogPath
        execution_report = (Join-Path $fullCaseOutput 'execution-report.md')
        executive_report = (Join-Path $fullCaseOutput 'executive\executive-report.md')
        claim_accuracy_report = (Join-Path $fullCaseOutput 'claim-accuracy\claim-accuracy.md')
    }
}
$manifestPath = Join-Path $OutputRoot 'live-demo-manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$manifest | ConvertTo-Json -Depth 8
