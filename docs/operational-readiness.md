# Operational Readiness

## Production Shape

Find Evil SIFT is designed as a controlled forensic workflow rather than an
unbounded guest shell:

- Guest evidence paths must live below `/cases`.
- Shareable host VM settings can live in a JSON host config while guest secrets
  remain environment-provided.
- Optional reference corpora are cataloged as guidance sources with hashes and
  a strict reporting boundary outside case evidence.
- Case plans are validated before VMware guest work begins.
- Each lane has a narrow operation set and produces structured JSON plus
  preserved raw outputs.
- Evidence hashes are captured before and after analysis.
- The case workflow follows a JSON case plan and validates configured benchmark
  manifests before producing downstream outputs.
- The R&M scenario profile is data-driven and separated from generic evidence
  triage code.

## Analyst Workflow

The one-command workflow returns three levels of output:

| Output | Purpose |
| --- | --- |
| Lane bundles | Evidence hashes, human reports, and preserved tool output per artifact source. |
| Correlation bundle | Cross-artifact pivots such as domain context and persistence corroboration. |
| Claim review bundles | Claim ledger, capped quality-review trace, and optional labeled claim-accuracy score. |
| Case dossier | Optional profile background, evidence relationships, and scenario-alignment score. |
| Executive report | Leadership-facing scope, supported triage signals, caveats, and next actions. |

This split is deliberate. A SOC or IR team can use the lane summaries as
machine-readable inputs, the correlation report for triage handoff, and the
dossier for quality control against a known case profile.

## Reliability Controls

- Configured benchmarks fail closed for missing required pivots.
- Plan validation fails closed for unsupported lanes, unsafe output paths,
  missing memory terms, and missing configured profile references.
- Workflow retries are bounded and logged.
- The execution trace records lane timing, validation scores, evidence caveats,
  correlation completion, and scenario alignment.
- The disk lane records the EWF corruption flag and the workflow shifts host
  persistence review to exported Autoruns, protected registry material, and
  exported UserAssist context.
- The memory lane is intentionally bounded to explicit string terms and reports
  volatile pivots without converting them into process conclusions.
- The UserAssist lane preserves timestamped execution context from exported
  NTUSER hives and promotes it only when correlation aligns it with host pivots.

## Next Hardening

- Extend configuration from host VM settings into output retention and profile
  selection policy.
- Build retrieval on top of cataloged operator references only after guidance
  output stays visibly separate from evidence-backed claims.
- Add signed run manifests for bundles that leave the workstation.
- Add memory-forensics plugins and broader disk extraction only when preserved
  outputs can support stronger findings than the current quick-response lanes.
