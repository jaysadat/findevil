# Find Evil SIFT Lab

This repository is the separate working project for the 2026 Find Evil
Protocol SIFT hackathon. It is a production-shaped DFIR workflow around a SANS
SIFT VM: constrained evidence lanes, evidence integrity records, case plans,
optional benchmark validation, cross-artifact correlation, and analyst-facing
reports.

## Direction

The current workflow is organized around a narrow, defensible control plane:

1. Verify the SIFT lab can be controlled reproducibly from the Windows host.
2. Add constrained forensic tools with structured outputs and evidence logs.
3. Drive multi-artifact investigations from case plans instead of hardcoded
   evidence paths.
4. Expand only after the evidence-integrity and audit story is solid.

The reusable workflow entrypoint is `run-case`. A JSON case plan names the
evidence lanes to run, their guest paths below `/cases`, memory search terms
when needed, optional benchmark manifests, and an optional scenario profile.
The bundled R&M plan is a regression fixture for DFIR Madness Case 001, The
Stolen Szechuan Sauce. It proves the workflow against a known multi-artifact
case without making those facts the default product behavior.

## Quick Start

1. Create the local environment and install the project:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -e .
   ```

2. Copy `config/sift-host.example.json` to ignored `config/sift-host.json`
   and set the local `vmx_path`.
3. Set the host config and guest password in the current shell:

   ```powershell
   $env:FINDEVIL_SIFT_CONFIG='config\sift-host.json'
   $env:SIFT_GUEST_PASSWORD='<guest-password>'
   ```

4. Run the host probe:

   ```powershell
   .\scripts\probe-sift.ps1
   ```

5. Review the returned JSON before adding deeper automation.

Explicit CLI VMX overrides win over `SIFT_VMX_PATH`, environment VM settings
win over the host config file, and the config file wins over built-in VMware
defaults. Guest passwords are intentionally rejected from host config files.
The same host config can set workflow operator policy: allowed output roots and
whether `run-case` must have `FINDEVIL_RUN_MANIFEST_KEY` before guest work
starts. It can also approve local guidance index roots. Relative policy roots
resolve from the host config directory.

Run the local audit primitive tests with:

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests -v
```

Optional local reference PDFs can be cataloged separately from evidence. Start
from `knowledge/corpus.example.json`, keep any local manifest and indexes
ignored, and write the catalog into `artifacts/`:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-knowledge-manifest `
  '.\knowledge\corpus.example.json'
.\.venv\Scripts\findevil-sift.exe catalog-knowledge `
  '.\knowledge\corpus.example.json' `
  --output-dir '.\artifacts\knowledge-catalog'
```

Knowledge catalogs preserve source hashes and scope for operator references.
They are guidance for plans and next actions, not evidence support for findings.
Use `index-knowledge` and `query-knowledge` after cataloging when a bounded
local guidance search is useful; query hits stay labeled separately from case
evidence outputs. `validate-knowledge-guidance` checks approved indexes against
expected-hit fixtures before guidance is used for automation. `draft-guidance-plan`
writes a review-only planning artifact; it does not create executable case
plans.

The first constrained local tool is a read-only evidence hash operation:

```powershell
$env:PYTHONPATH='src'
python -m findevil_sift.cli hash-evidence .\README.md
```

The first SIFT-backed product lane is PCAP triage:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
$env:PYTHONPATH='src'
python -m findevil_sift.cli pcap-triage `
  '/cases/R&M/case001-pcap/case001.pcap' `
  --output-dir '.\artifacts\rm-case001-pcap'
```

See `docs/product.md` for the MCP server path.

The bundled sample plan is:

- `cases/rm-stolen-szechuan-sauce.json`

Start a new editable plan with:

```powershell
.\.venv\Scripts\findevil-sift.exe init-case-plan `
  '.\cases\acme-incident.json' `
  --case-id 'acme-incident' `
  --case-name 'ACME Incident'
```

Or inventory a SIFT case root and draft one for review:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift.exe discover-case `
  '/cases/acme' `
  --output-dir '.\artifacts\acme-discovery' `
  --plan-output '.\cases\acme-discovered.json' `
  --case-id 'acme-discovered' `
  --case-name 'ACME Discovered Case'
```

Validate a plan before a SIFT run:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-case-plan `
  '.\cases\acme-incident.json'
```

Its benchmark manifests cover the sample PCAP, DC disk, DC Autoruns, protected
registry, UserAssist, and DC memory lanes, plus an optional R&M case profile:

- `benchmarks/rm-case001-pcap.json`
- `benchmarks/rm-dc-disk.json`
- `benchmarks/rm-dc-autoruns.json`
- `benchmarks/rm-dc-registry.json`
- `benchmarks/rm-dc-userassist.json`
- `benchmarks/rm-dc-memory.json`
- `benchmarks/rm-stolen-szechuan-sauce-profile.json`

After installing the project into `.venv`, the sample PCAP fixture script runs
triage and validation together:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\scripts\run-rm-pcap-demo.ps1
```

The two-lane sample fixture runs the PCAP and DC disk paths together:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\scripts\run-rm-two-lane-demo.ps1
```

Run a plan-driven case workflow:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift.exe run-case `
  '.\cases\rm-stolen-szechuan-sauce.json' `
  --output-dir '.\artifacts\sample-case'
```

The R&M sample helper script invokes the same product command:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\scripts\run-rm-case-demo.ps1
```

For a recording path that includes discovery, the memory-lane correction event,
and the full benchmarked case run:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\scripts\run-rm-live-demo.ps1 -OutputRoot '.\artifacts\rm-live-demo'
```

That script writes `live-demo-manifest.json` with the draft plan, correction
execution log, full-case execution log, executive report, and claim-accuracy
report paths.

During a time-boxed recording, use the quick real-case correction path and
show the prepared full-case manifest outputs afterward:

```powershell
.\scripts\run-rm-live-demo.ps1 `
  -OutputRoot '.\artifacts\rm-live-correction' `
  -QuickCorrection `
  -CorrectionOnly
```

The workflow emits `execution-log.json` and `execution-report.md` beside lane
bundles. Plans with PCAP and disk lanes also emit a correlation bundle. Plans
with a scenario profile emit a dossier after validation. Benchmark manifests
are optional; when provided, retries are bounded and logged. Every completed
workflow also emits `executive/executive-report.md` for status, scope, supported
triage signals, caveats, and next actions. Correlated runs also emit
`claims/claim-ledger.md` so pivot claims stay labeled and traceable, plus
`quality/quality-review.md` with the capped promotion-review iteration trace.
Plans with an optional labeled claim-accuracy manifest also emit
`claim-accuracy/claim-accuracy.md` to score promoted, missed, rejected, and
unsafe claim classes at the review boundary.

Each workflow output root also gets `run-manifest.json` with SHA-256 hashes for
the exported bundle. Set `FINDEVIL_RUN_MANIFEST_KEY` before a run to add an
HMAC-SHA256 export signature, then verify hashes and any signature with:

```powershell
$env:FINDEVIL_RUN_MANIFEST_KEY='<local-export-key>'
.\.venv\Scripts\findevil-sift.exe verify-run-manifest `
  '.\artifacts\sample-case\run-manifest.json'
```

## Layout

- `docs/` contains product notes, case-plan guidance, and architecture notes.
- `scripts/` contains host-side lab controls.
- `src/` contains the first evidence-safe primitives and constrained tools.
- Future code should separate the trusted tool layer, agent orchestration,
  benchmark fixtures, and generated investigation artifacts.
