# Case Plans

`run-case` is the product workflow entrypoint. It reads a JSON plan rather than
hardcoding evidence paths or scenario facts.

## Discover From SIFT

Inventory a case folder and draft a reviewable plan:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift.exe discover-case `
  '/cases/acme' `
  --output-dir '.\artifacts\acme-discovery' `
  --plan-output '.\cases\acme-discovered.json' `
  --case-id 'acme-discovered' `
  --case-name 'ACME Discovered Case'
```

Discovery writes `inventory.json`, `report.md`, and a guest run log. It
classifies current lane candidates by suffix and bounded ZIP member inspection:
PCAP, E01 primary segment, memory image, Autoruns CSV ZIP, protected
SOFTWARE/SYSTEM ZIP, and exported NTUSER ZIP for UserAssist. One ZIP can emit
both registry and UserAssist candidates when it contains both protected hives
and exported user hives. When a draft plan is requested, it preserves multiple
candidates for a lane under `artifacts` and records selection counts and review
requirements in the plan.

Review discovered paths before `run-case`. Multiple candidates in one lane are
kept in the draft plan, and discovery marks that lane as `review_required`.
Memory draft plans keep `pivot-to-review` as a placeholder term until an
analyst supplies pivots. If that placeholder reaches `run-case`, the workflow
records a `lane_adjusted` event and skips bounded memory triage until explicit
case pivots are supplied.

Create a template when the evidence paths are already known:

```powershell
.\.venv\Scripts\findevil-sift.exe init-case-plan `
  '.\cases\acme-2026-05-incident.json' `
  --case-id 'acme-2026-05-incident' `
  --case-name 'ACME May Incident'
```

Omit `--lane` to include every current lane. Repeat `--lane` to start with a
smaller plan:

```powershell
.\.venv\Scripts\findevil-sift.exe init-case-plan `
  '.\cases\acme-network-host.json' `
  --case-id 'acme-network-host' `
  --case-name 'ACME Network And Host' `
  --lane pcap `
  --lane disk
```

## Minimal Shape

```json
{
  "case_id": "acme-2026-05-incident",
  "case_name": "ACME May Incident",
  "lanes": {
    "pcap": {
      "guest_path": "/cases/acme/network/edge.pcap"
    },
    "disk": {
      "guest_path": "/cases/acme/host01/image.E01"
    },
    "memory": {
      "guest_path": "/cases/acme/host01/memory.mem",
      "terms": ["suspect.exe", "203.0.113.10"]
    }
  }
}
```

Supported lane keys are `pcap`, `disk`, `autoruns`, `registry`, `userassist`,
and `memory`. Each lane writes to a same-named output directory unless
`output_dir` is set. The memory lane requires explicit `terms`.

## Multiple Artifacts

Use `artifacts` when one lane has several sources, such as Autoruns exports
from multiple hosts:

```json
{
  "lanes": {
    "autoruns": {
      "artifacts": [
        {"guest_path": "/cases/acme/host-a/autoruns.zip"},
        {"guest_path": "/cases/acme/host-b/autoruns.zip"}
      ]
    }
  }
}
```

Single-artifact lane objects remain valid. A multi-artifact run writes separate
lane bundles such as `autoruns-01` and `autoruns-02` unless an artifact sets an
explicit `output_dir`. Current correlation and optional scenario alignment use
the first artifact from each required lane; all configured artifacts still get
their own triage bundles and appear in the executive evidence count.

## Validate Before Run

```powershell
.\.venv\Scripts\findevil-sift.exe validate-case-plan `
  '.\cases\acme-2026-05-incident.json' `
  --output '.\artifacts\acme-plan-validation.json'
```

Validation checks:

- JSON shape, `case_id`, `case_name`, and configured lanes.
- Supported lane keys and lane configuration objects.
- Guest evidence paths remain below `/cases`.
- Optional workflow output directories remain relative to the run output root.
- Memory lanes include explicit non-empty terms.
- Optional benchmark manifests, claim-accuracy manifests, and scenario profiles
  resolve to existing files.

`run-case` performs the same validation before VMware guest work begins.

## Optional Validation

Add `benchmark_manifest` to a lane when a known fixture or QA profile should
be validated:

```json
{
  "guest_path": "/cases/acme/network/edge.pcap",
  "benchmark_manifest": "../benchmarks/acme-edge-pcap.json"
}
```

Benchmarks are optional product controls. They are useful for regression
fixtures, lab validation, and known-good workflow checks.

## Optional Scenario Profile

Add `scenario_profile` when a known training or regression scenario should emit
a dossier with expected pivots:

```json
{
  "scenario_profile": "../benchmarks/rm-stolen-szechuan-sauce-profile.json"
}
```

Scenario profiles are not required for normal case triage. They exist to keep
ground-truth checks outside the generic lane analyzers.

## Optional Claim Accuracy Manifest

Add `claim_accuracy_manifest` when a labeled case should score the claim-review
boundary after correlation:

```json
{
  "claim_accuracy_manifest": "../benchmarks/acme-claim-accuracy.json"
}
```

The manifest names expected promoted claim types, expected blocked claim types,
and statuses that must never be promoted. The workflow writes
`claim-accuracy/claim-accuracy.json` and `claim-accuracy/claim-accuracy.md`
when the claim ledger and quality review exist. This is a regression and
evaluation control for known cases; it is not required for ordinary triage.
