# Submission Readiness

## Current Shape

Find Evil SIFT currently follows the custom MCP server path:

- Constrained SIFT guest lanes for PCAP, mount-free E01 inventory, exported
  Autoruns CSV triage, protected SOFTWARE/SYSTEM hive triage, exported
  UserAssist triage, and bounded memory string triage.
- Plan-driven host orchestration with optional benchmark validation and case
  correlation.
- Optional profile-driven dossier checks for known regression or training
  scenarios.
- A one-command `run-case` workflow with timestamped execution logs, bounded
  retry hooks for configured benchmarks, failed-artifact continuation, and
  recorded evidence caveats.

## Required Submission Components

| Component | Current Status |
| --- | --- |
| Public code repository and open-source license | Repository structure and `LICENSE` exist; publish when ready. |
| Demo video | `docs/demo-script.md`, `scripts/run-rm-live-demo.ps1`, and `scripts/run-submission-package.ps1` map discovery, correction, full run, guidance review, run-manifest verification, and report handoff into a five-minute recording path. |
| Architecture diagram | `docs/architecture.md` has the current trust-boundary diagram. |
| Written project description | `docs/devpost-package.md` plus `README.md`, `docs/product.md`, and accuracy notes. |
| Dataset documentation | PCAP, DC disk, DC Autoruns, protected registry, UserAssist, and memory notes exist in `docs/`. |
| Accuracy report | `docs/accuracy-report.md` covers current benchmark behavior and limits. |
| Try-it-out instructions | `README.md` and `docs/product.md` describe local SIFT setup and workflow commands. |
| Agent execution logs | `run-case` emits `execution-log.json` and `execution-report.md`; the submission package writes `live-demo-manifest.json`, run-manifest verification JSON, and `submission-summary.json` with the log/report paths. |

The last exercised VMware-backed path is recorded in
`docs/live-run-validation.md`.

## Highest-Value Next Work

1. Run `scripts/run-submission-package.ps1` for the final artifact bundle and
   record the five-minute demo.
2. Add lane-specific recovery decisions where a safer alternate artifact or
   parameter set can replace a failed path.

See `docs/judging-alignment.md` for the criterion-by-criterion gap analysis.
