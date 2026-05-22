# Devpost Package Draft

## One-Line Pitch

Find Evil SIFT is a constrained autonomous DFIR case workflow that inventories
SIFT evidence, runs evidence-safe triage lanes, correlates host and network
pivots, and preserves a reviewable claim trail before executive handoff.

## What It Does

Find Evil SIFT wraps a SANS SIFT VM with a host-side control plane instead of
giving an agent an unbounded guest shell. A JSON case plan selects evidence
lanes under `/cases`, optional benchmark manifests, and optional labeled
evaluation controls. The workflow can discover case candidates, execute
allowlisted guest analyzers, verify before/after evidence hashes, preserve raw
tool outputs, correlate pivots, run a capped claim-promotion review, score
known claim-review behavior, and write both analyst and executive reports.

The current product has six constrained evidence lanes:

| Lane | Purpose |
| --- | --- |
| PCAP | Offline Zeek network pivots and raw Zeek logs. |
| Disk | Mount-free E01 Sleuth Kit inventory and disk caveats. |
| Autoruns | Exported startup surface and persistence review pivots. |
| Registry | Protected SOFTWARE/SYSTEM Run, service, and decoded payload context. |
| UserAssist | Exported NTUSER timestamped execution context. |
| Memory | Explicit bounded memory-string pivot preservation. |

## How We Built It

The project uses a custom MCP server and typed host CLI around VMware guest
operations. Host-side workflow code copies narrow Python analyzers into the
SIFT guest, runs only the lane operations those analyzers allow, and copies
structured summaries plus preserved raw output bundles back to the host.
Case-plan manifests keep sample ground truth and regression expectations out of
generic artifact analyzers.

Each workflow run can validate configured benchmark manifests, correlate PCAP
and host pivots, build a claim ledger, run a capped quality review, optionally
score claim-review behavior against a labeled manifest, and produce an executive
handoff that keeps quick pivots separate from analyst-approved findings.

## Challenges

- Keeping the system autonomous without turning the SIFT VM into an unbounded
  evidence-touching shell.
- Preserving useful real-case output without pushing massive raw tool text into
  an agent context window.
- Making the demo show genuine correction while a full multi-lane forensic run
  remains long-running and evidence-heavy.
- Distinguishing useful pivots from claims safe enough for executive handoff.

## What We Learned

- The `/cases` boundary, narrow guest analyzers, before/after hashes, and raw
  output preservation are easier to defend than prompt-only "be read-only"
  instructions.
- Discovery helps autonomy most when it records ambiguity. A generated memory
  placeholder should become a review decision, not an invented memory search.
- Correlation adds confidence only when reporting keeps candidate, volatile,
  corroborated, and supported claim classes visibly separate.

## Standout Points

- Autonomous case discovery drafts reviewable plans from evidence candidates.
- The workflow adapts away from underspecified discovered memory searches with
  a recorded `lane_adjusted` event.
- Failed planned artifacts are recorded as reviewable lane failures and the
  workflow continues with remaining artifacts and case lanes where summaries
  remain available.
- The corrupted sample E01 caveat is preserved and the workflow leans on
  exported host artifacts for stronger host follow-up.
- Cross-artifact confidence improves from PCAP/disk domain context to
  Autoruns/registry persistence corroboration and UserAssist execution context.
- Executive output is gated by a claim ledger and capped quality review.
- Known regression cases can add a claim-accuracy manifest to score promoted,
  blocked, missed, and unsafe claim classes.

## Architecture Evidence

Use `docs/architecture.md` in the submission:

- Windows host project and MCP/CLI control plane.
- VMware guest operations boundary.
- Allowlisted guest analyzers.
- Evidence scope below `/cases`.
- Host-side preserved JSON, reports, raw output ZIPs, and execution logs.

## Try It Out

Start with:

1. Install the package into `.venv`.
2. Set `SIFT_GUEST_PASSWORD`.
3. Run `scripts/probe-sift.ps1`.
4. Run `discover-case` for a case root or validate a JSON case plan.
5. Run `run-case`.

Use `README.md`, `docs/product.md`, and `docs/case-plans.md` for the exact
commands.

## Submission Artifact Map

| Submission Need | Repository Artifact |
| --- | --- |
| Public code and license | Repository root and `LICENSE` |
| Demo video path | `docs/demo-script.md` and `scripts/run-rm-live-demo.ps1` |
| Architecture with boundaries | `docs/architecture.md` |
| Written description | This file plus `README.md` and `docs/product.md` |
| Dataset documentation | `docs/dataset-*.md` and `docs/case-background.md` |
| Accuracy report | `docs/accuracy-report.md` and generated `claim-accuracy/` outputs |
| Try-it-out instructions | `README.md`, `docs/product.md`, `docs/case-plans.md` |
| Agent/tool audit trail | Generated `live-demo-manifest.json`, `execution-log.json`, `execution-report.md`, lane summaries, raw output ZIPs, claim ledger, quality review |

## Submission Notes

- Preserve the recorded terminal run, generated workflow artifacts, and the
  agent/tool-call export used to create the submission.
- Keep benchmark and scenario manifests labeled as evaluation controls so the
  product story stays generic for arbitrary cases.
- Link the R&M case dataset notes when describing the regression fixture.

## What's Next

- Record and upload the five-minute terminal demo using the quick real-case
  correction path and prepared full-run reports.
- Add lane-specific recovery that can choose a safer alternate artifact or
  parameter set after a lane failure.
- Deepen incident-level scoring beyond the current labeled claim-review
  boundary.
