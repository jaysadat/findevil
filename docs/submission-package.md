# Submission Package

Use `scripts/run-submission-package.ps1` to build the review bundle for the
Devpost submission. It wraps the live demo driver, verifies signed run
manifests, optionally evaluates the approved guidance index, writes a
review-only guidance plan draft, and emits `submission-summary.json` plus
`submission-summary.md`.

## Prepare

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
$env:FINDEVIL_SIFT_CONFIG='config\sift-host.json'
$env:SIFT_GUEST_PASSWORD='<guest-password>'
$env:FINDEVIL_RUN_MANIFEST_KEY='<local-export-key>'
$env:FINDEVIL_RUN_MANIFEST_KEY_ID='submission'
```

If using guidance retrieval, build and evaluate the local index first:

```powershell
.\.venv\Scripts\findevil-sift.exe catalog-knowledge `
  '.\knowledge\corpus.json' `
  --output-dir '.\artifacts\knowledge-catalog'
.\.venv\Scripts\findevil-sift.exe index-knowledge `
  '.\artifacts\knowledge-catalog\knowledge-catalog.json' `
  --output-dir '.\knowledge\indexes\operator-dfir-guidance'
.\.venv\Scripts\findevil-sift.exe validate-knowledge-guidance `
  '.\knowledge\indexes\operator-dfir-guidance\knowledge-index.json' `
  '.\benchmarks\guidance-evaluation.example.json'
```

## Full Package

```powershell
.\scripts\run-submission-package.ps1 `
  -OutputRoot '.\artifacts\submission-package-final'
```

The full package is best prepared before recording because it can run the
benchmarked multi-lane case.

## Five-Minute Recording Package

```powershell
.\scripts\run-submission-package.ps1 `
  -OutputRoot '.\artifacts\submission-package-recording' `
  -QuickCorrectionOnly
```

Use the quick package during the video to show live discovery and the
`lane_adjusted` memory self-correction event, then open the already prepared
full package reports for the complete benchmarked result.

## What To Submit

- Public repository: `https://github.com/jaysadat/findevil`
- Demo video following `docs/demo-script.md`
- Architecture diagram: `docs/architecture.md`
- Project description: `docs/devpost-package.md`
- Dataset notes: `docs/dataset-*.md` and `docs/case-background.md`
- Accuracy report: `docs/accuracy-report.md`
- Try-it-out instructions: `README.md`, `docs/product.md`, and `docs/case-plans.md`
- Execution logs and reports from `submission-summary.json`
