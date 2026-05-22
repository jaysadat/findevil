# Five-Minute Demo Runbook

## Goal

Show Find Evil SIFT as an autonomous constrained case workflow, not a parser
collection:

1. Discover evidence in a SIFT case folder.
2. Show a recorded correction when a discovered memory plan is still
   underspecified.
3. Run the benchmarked multi-artifact case plan.
4. Hand off executive, claim, quality, accuracy, and raw-evidence outputs.

## Recording Setup

Prepare before recording:

- SIFT VM is reachable through VMware Tools.
- `SIFT_GUEST_PASSWORD` is set in the PowerShell shell.
- The project is installed in `.venv`.
- Terminal font is large enough to read JSON scores and artifact paths.

Use the R&M fixture for the recorded path:

```powershell
.\.venv\Scripts\findevil-sift.exe discover-case `
  '/cases/R&M' `
  --output-dir '.\artifacts\demo-discovery' `
  --plan-output '.\artifacts\demo-discovery\rm-discovered.json' `
  --case-id 'demo-discovered' `
  --case-name 'Demo Discovered Case'
```

## Timeline

| Time | Screen | Narration Point |
| --- | --- | --- |
| 0:00 | `README.md` and architecture diagram | Host orchestration drives allowlisted guest analyzers against `/cases` evidence. |
| 0:25 | `discover-case` JSON output | The agent inventories lane candidates and drafts a reviewable plan rather than assuming one evidence path. |
| 0:55 | Discovered plan memory lane | The memory lane carries `pivot-to-review` until explicit pivots exist. |
| 1:10 | Run discovered plan or show its execution event | `run-case` records `lane_adjusted` and skips that non-actionable memory search instead of spending evidence time on a fake term. |
| 1:35 | Benchmarked sample plan | The known case fixture supplies explicit memory pivots and optional evaluation manifests outside generic analyzers. |
| 1:50 | `scripts/run-rm-case-demo.ps1` or `run-case` | One command executes six constrained lanes, benchmarks them, correlates outputs, and writes audit artifacts. |
| 4:05 | `execution-report.md` | Point to validation scores, disk corruption caveat, correlation, claim review, and claim accuracy events. |
| 4:25 | `executive-report.md` | Leadership gets scope, caveats, and promoted triage signals only. |
| 4:40 | `claim-accuracy.md` and raw lane bundles | The reporting gate counts expected promoted and rejected claim classes while raw Zeek, RegRipper, UserAssist, and memory outputs remain preserved. |

## Live Commands

Prepare the full recording artifact set before the time-boxed capture:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\scripts\run-rm-live-demo.ps1 -OutputRoot '.\artifacts\rm-live-demo'
```

That driver preserves discovery output, the correction run, the benchmarked
full case run, and `live-demo-manifest.json` with the report and log paths to
open during narration.

For the live five-minute capture, run the short real-case correction path:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\scripts\run-rm-live-demo.ps1 `
  -OutputRoot '.\artifacts\rm-live-correction' `
  -QuickCorrection `
  -CorrectionOnly
```

The quick path discovers the real case, derives a memory review plan from the
discovered memory evidence, and records the same `lane_adjusted` event without
waiting for the full six-lane benchmark run on camera.

Manual correction path:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift.exe run-case `
  '.\artifacts\demo-discovery\rm-discovered.json' `
  --output-dir '.\artifacts\demo-discovered-run'
```

Full benchmarked path:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\scripts\run-rm-case-demo.ps1 -OutputRoot '.\artifacts\demo-full-case'
```

## Outputs To Open

- `artifacts/demo-full-case/execution-report.md`
- `artifacts/demo-full-case/executive/executive-report.md`
- `artifacts/demo-full-case/correlation/correlation.md`
- `artifacts/demo-full-case/quality/quality-review.md`
- `artifacts/demo-full-case/claim-accuracy/claim-accuracy.md`
- `artifacts/demo-full-case/dc-userassist/report.md`

## Claims To Avoid

- Do not call quick pivots confirmed malicious findings.
- Do not imply UserAssist proves malware behavior by itself.
- Do not hide the E01 corruption caveat; it is part of the product decision
  story.
- Do not present the R&M profile as product hardcoding. It is a labeled
  regression fixture outside the generic lane analyzers.
