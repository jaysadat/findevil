[CmdletBinding()]
param(
    [string]$OutputRoot = ".\artifacts\submission-package",
    [string]$GuestCaseRoot = "/cases/R&M",
    [string]$KnowledgeIndex = ".\knowledge\indexes\operator-dfir-guidance\knowledge-index.json",
    [string]$GuidanceEvaluation = ".\benchmarks\guidance-evaluation.example.json",
    [string]$GuidanceContext = "memory process persistence review for suspect.exe with network pcap and host artifact pivots",
    [switch]$QuickCorrectionOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:SIFT_GUEST_PASSWORD)) {
    throw "Set SIFT_GUEST_PASSWORD before building the submission package."
}

if ([string]::IsNullOrWhiteSpace($env:FINDEVIL_RUN_MANIFEST_KEY)) {
    throw "Set FINDEVIL_RUN_MANIFEST_KEY so submission run manifests are signed and verifiable."
}

$cli = Join-Path $PSScriptRoot "..\.venv\Scripts\findevil-sift.exe"
if (-not (Test-Path -LiteralPath $cli)) {
    throw "Install the project into .venv first: .\.venv\Scripts\python.exe -m pip install -e ."
}

if (Test-Path -LiteralPath $OutputRoot) {
    throw "Submission output root already exists: $OutputRoot"
}

function Invoke-FindEvil {
    param([string[]]$Arguments)

    & $cli @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "findevil-sift exited with code $LASTEXITCODE while running: $($Arguments -join ' ')"
    }
}

if ($QuickCorrectionOnly) {
    & (Join-Path $PSScriptRoot "run-rm-live-demo.ps1") `
        -OutputRoot $OutputRoot `
        -GuestCaseRoot $GuestCaseRoot `
        -QuickCorrection `
        -CorrectionOnly
} else {
    & (Join-Path $PSScriptRoot "run-rm-live-demo.ps1") `
        -OutputRoot $OutputRoot `
        -GuestCaseRoot $GuestCaseRoot
}
if ($LASTEXITCODE -ne 0) {
    throw "run-rm-live-demo.ps1 exited with code $LASTEXITCODE."
}

$liveManifestPath = Join-Path $OutputRoot "live-demo-manifest.json"
$liveManifest = Get-Content -Raw -LiteralPath $liveManifestPath | ConvertFrom-Json

$verifications = @()
$correctionManifest = Join-Path $OutputRoot "correction-run\run-manifest.json"
if (Test-Path -LiteralPath $correctionManifest) {
    $verificationPath = Join-Path $OutputRoot "correction-run-manifest-verification.json"
    Invoke-FindEvil @("verify-run-manifest", $correctionManifest) |
        Set-Content -LiteralPath $verificationPath -Encoding utf8
    $verifications += [ordered]@{
        name = "correction-run"
        manifest = $correctionManifest
        verification = $verificationPath
    }
}

$fullManifest = Join-Path $OutputRoot "full-case\run-manifest.json"
if (Test-Path -LiteralPath $fullManifest) {
    $verificationPath = Join-Path $OutputRoot "full-case-run-manifest-verification.json"
    Invoke-FindEvil @("verify-run-manifest", $fullManifest) |
        Set-Content -LiteralPath $verificationPath -Encoding utf8
    $verifications += [ordered]@{
        name = "full-case"
        manifest = $fullManifest
        verification = $verificationPath
    }
}

$guidance = $null
if (-not [string]::IsNullOrWhiteSpace($KnowledgeIndex) -and (Test-Path -LiteralPath $KnowledgeIndex)) {
    $guidanceRoot = Join-Path $OutputRoot "guidance"
    New-Item -ItemType Directory -Force -Path $guidanceRoot | Out-Null
    $evaluationPath = Join-Path $guidanceRoot "knowledge-guidance-evaluation.json"
    if (-not [string]::IsNullOrWhiteSpace($GuidanceEvaluation) -and (Test-Path -LiteralPath $GuidanceEvaluation)) {
        Invoke-FindEvil @(
            "validate-knowledge-guidance",
            $KnowledgeIndex,
            $GuidanceEvaluation,
            "--output", $evaluationPath
        ) | Out-Null
    }
    $draftOutput = Join-Path $guidanceRoot "plan-draft"
    Invoke-FindEvil @(
        "draft-guidance-plan",
        $KnowledgeIndex,
        "--case-id", "submission-guidance",
        "--case-name", "Submission Guidance Draft",
        "--context", $GuidanceContext,
        "--output-dir", $draftOutput
    ) | Out-Null
    $guidance = [ordered]@{
        index = $KnowledgeIndex
        evaluation = if (Test-Path -LiteralPath $evaluationPath) { $evaluationPath } else { $null }
        plan_draft = (Join-Path $draftOutput "guidance-plan-draft.json")
        plan_draft_report = (Join-Path $draftOutput "guidance-plan-draft.md")
    }
}

$components = [ordered]@{
    code_repository = "https://github.com/jaysadat/findevil"
    demo_video_runbook = "docs/demo-script.md"
    architecture_diagram = "docs/architecture.md"
    written_project_description = "docs/devpost-package.md"
    dataset_documentation = "docs/dataset-*.md and docs/case-background.md"
    accuracy_report = "docs/accuracy-report.md"
    try_it_out = "README.md and docs/product.md"
    execution_logs = $liveManifestPath
}

$summary = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    status = "ready_for_review"
    output_root = $OutputRoot
    quick_correction_only = [bool]$QuickCorrectionOnly
    guest_case_root = $GuestCaseRoot
    required_components = $components
    live_demo_manifest = $liveManifestPath
    correction_run = $liveManifest.correction_run
    full_case = if ($liveManifest.PSObject.Properties.Name -contains "full_case") { $liveManifest.full_case } else { $null }
    run_manifest_verifications = $verifications
    guidance = $guidance
    review_notes = @(
        "Record the five-minute video from the quick correction path and open prepared full-case reports.",
        "Show the lane_adjusted memory correction event as the self-correction sequence.",
        "Open execution-report.md, executive-report.md, claim-accuracy.md, and run-manifest verification output.",
        "Do not present guidance drafts as evidence or executable case plans."
    )
}

$summaryJson = Join-Path $OutputRoot "submission-summary.json"
$summaryMd = Join-Path $OutputRoot "submission-summary.md"
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryJson -Encoding utf8

$fullCaseLines = @()
if ($null -ne $summary.full_case) {
    $fullCaseLines += "- Full case execution log: ``$($summary.full_case.execution_log)``"
    $fullCaseLines += "- Full case executive report: ``$($summary.full_case.executive_report)``"
    $fullCaseLines += "- Full case claim accuracy report: ``$($summary.full_case.claim_accuracy_report)``"
} else {
    $fullCaseLines += "- Full case was skipped for this quick correction package."
}

$verificationLines = ($verifications | ForEach-Object {
    "- $($_.name): manifest ``$($_.manifest)``, verification ``$($_.verification)``"
}) -join [Environment]::NewLine
if ([string]::IsNullOrWhiteSpace($verificationLines)) {
    $verificationLines = "- No run manifests were found to verify."
}

$guidanceLines = @()
if ($null -ne $guidance) {
    $guidanceLines += "- Guidance evaluation: ``$($guidance.evaluation)``"
    $guidanceLines += "- Guidance plan draft: ``$($guidance.plan_draft_report)``"
} else {
    $guidanceLines += "- Guidance index was not supplied or not found."
}

$reviewLines = $summary.review_notes | ForEach-Object { "- $_" }
$markdown = @(
    "# Find Evil Submission Package",
    "",
    "Generated: $($summary.generated_at)",
    "",
    "## Status",
    "",
    "- Status: ``$($summary.status)``",
    "- Output root: ``$OutputRoot``",
    "- Guest case root: ``$GuestCaseRoot``",
    "- Quick correction only: ``$([bool]$QuickCorrectionOnly)``",
    "",
    "## Required Components",
    "",
    "- Code repository: $($components.code_repository)",
    "- Demo video runbook: ``$($components.demo_video_runbook)``",
    "- Architecture diagram: ``$($components.architecture_diagram)``",
    "- Written project description: ``$($components.written_project_description)``",
    "- Dataset documentation: ``$($components.dataset_documentation)``",
    "- Accuracy report: ``$($components.accuracy_report)``",
    "- Try-it-out instructions: ``$($components.try_it_out)``",
    "- Agent/tool execution logs: ``$($components.execution_logs)``",
    "",
    "## Demo Outputs",
    "",
    "- Live demo manifest: ``$liveManifestPath``",
    "- Correction execution log: ``$($summary.correction_run.execution_log)``",
    "- Correction execution report: ``$($summary.correction_run.execution_report)``",
    "",
    $fullCaseLines,
    "",
    "## Run Manifest Verification",
    "",
    $verificationLines,
    "",
    "## Guidance Review",
    "",
    $guidanceLines,
    "",
    "## Review Notes",
    "",
    $reviewLines
)
$markdown | Set-Content -LiteralPath $summaryMd -Encoding utf8

$summary | ConvertTo-Json -Depth 10
