# Product Prototype

## Name

Find Evil SIFT is a constrained case-triage layer for SANS SIFT.

Host VMware settings can be supplied through `FINDEVIL_SIFT_CONFIG` using the
shape in `config/sift-host.example.json`. The file may name the VMX path, guest
user, and `vmrun` path, but it must not contain guest passwords or tokens.
Secrets remain environment-provided so shareable host profiles do not become
credential bundles.

The same host config can define `operator_policy` for plan-driven workflow
runs. `allowed_output_roots` constrains `run-case` output directories before
guest work begins. `require_signed_run_manifests` requires
`FINDEVIL_RUN_MANIFEST_KEY` before workflow output starts. Relative allowed
roots resolve from the host config directory, so the example config can keep
artifacts under the repository while a deployed profile can point at a case
workspace. `approved_knowledge_index_roots` does the same for queried and
evaluated local guidance indexes.

Operator PDF and runbook references can be cataloged through a separate
knowledge manifest described in `docs/knowledge-corpus.md`. Those sources are
guidance inputs for future plan or next-action assistance, not evidence inputs
for reports or claim promotion. A bounded lexical index can consume the
catalog, re-check source hashes before extraction, and return labeled guidance
chunks for analyst review without entering claim promotion. Guidance can also
write a review-only planning draft with suggested lanes and next actions, but
it does not create or modify executable case plans.

## Current Capability

The prototype currently has six evidence lanes plus a host-side correlation
step.

PCAP triage accepts an existing PCAP path below `/cases` in the SIFT guest,
runs an allowlisted offline analysis path, and returns:

- `summary.json` with evidence hashes, command records, Zeek pivots, and log
  inventory.
- `report.md` with a human-readable triage report.
- `zeek-logs.zip` with raw Zeek outputs copied back from the guest.
- `guest-run.log` with guest analyzer execution output.

The analyzer records the PCAP SHA-256 before and after analysis and reports
whether the evidence changed.

Mount-free disk triage accepts an E01 primary segment below `/cases`, uses
Sleuth Kit directly against the image, and returns:

- `summary.json` with EWF segment hashes, command records, partition metadata,
  filesystem metadata, and Windows/DC artifact pivots.
- `report.md` with a disk triage report.
- `tsk-outputs.zip` with `ewfinfo`, `mmls`, `fsstat`, and recursive `fls`
  output.
- `guest-run.log` with guest analyzer execution output.

Autoruns triage accepts an exported ZIP below `/cases` with exactly one
Autoruns CSV member and returns:

- `summary.json` with ZIP hashes, row counts, signer counts, review candidates,
  and a narrower high-signal persistence pivot list.
- `report.md` with the evidence surface and high-signal rows called out first.
- `autoruns-outputs.zip` with the decoded CSV exported from the evidence ZIP.
- `guest-run.log` with guest analyzer execution output.

Protected registry triage accepts the protected-files ZIP below `/cases`,
extracts the exported SOFTWARE and SYSTEM hives, and returns:

- `summary.json` with ZIP hashes, parsed Run and service entries, and high-signal
  registry persistence pivots.
- `report.md` with the Run/service surface and protected-hive persistence
  pivots.
- `registry-outputs.zip` with RegRipper `run` and `services` output.
- `guest-run.log` with guest analyzer execution output.

UserAssist triage accepts a ZIP below `/cases` with exported
`Users/<profile>/NTUSER.DAT` hives and returns:

- `summary.json` with ZIP hashes, exported hive members, timestamped UserAssist
  execution entries, and execution review pivots.
- `report.md` with the exported user-hive surface and preserved execution
  context.
- `userassist-outputs.zip` with RegRipper `userassist` output for each exported
  hive.
- `guest-run.log` with guest analyzer execution output.

Bounded memory triage accepts a memory image below `/cases` plus explicit
search terms and returns:

- `summary.json` with memory hashes, string-hit counts, and sampled ASCII or
  UTF-16LE hit lines.
- `report.md` with volatile pivot counts and examples.
- `memory-string-hits.zip` with matching string lines preserved outside the
  model response.
- `guest-run.log` with guest analyzer execution output.

The host-side correlation step links PCAP DNS hints to disk SYSVOL hints,
surfaces candidate domain-controller network pivots, and can attach the
high-signal Autoruns persistence pivots without promoting them to confirmed
findings. When registry output is provided, it marks persistence names shared
by Autoruns and protected registry evidence as corroborated pivots. When memory
output is provided, it carries explicit string-hit pivots as volatile support
for follow-up. When UserAssist output is provided, it can corroborate timestamped
execution context against host high-signal persistence pivots without treating
UserAssist as malware classification.

The plan-driven case workflow is the autonomous path through those lanes. A
case plan selects evidence lanes, guest evidence paths, bounded memory terms,
optional benchmark manifests, and an optional scenario profile. The workflow
runs triage, validates configured benchmarks, retries failed benchmark
validation with a bounded attempt cap, records failed planned artifacts as
reviewable lane adjustments, records timestamped events, and emits correlation
when the required lane summaries exist.

Each lane can contain one artifact or an `artifacts` list. Multi-artifact lanes
produce separate preserved bundles for each source. If one planned artifact
fails, the workflow continues with remaining artifacts and case lanes while the
failed artifact remains visible in the execution trace. The current correlation
layer consumes the first completed artifact from each required lane while the
workflow and executive evidence count preserve the wider lane scope.

Before a run, the case-plan validator rejects unsupported lanes, guest evidence
paths outside `/cases`, unsafe output directory traversal, memory lanes without
explicit terms, and missing benchmark/profile/claim-accuracy references.

For new cases, discovery can inventory one case root below `/cases`, preserve a
candidate report, and draft a reviewable case plan. Discovery is heuristic and
retains candidate ambiguity for analyst review instead of treating a selected
path as ground truth. If a discovered memory lane still contains the
`pivot-to-review` placeholder at execution time, the workflow records a lane
adjustment and skips that memory search until explicit case pivots exist.

The bundled R&M plan is a regression fixture. Its scenario dossier adds known
case background and alignment checks without embedding those expectations in
the product lane analyzers or the generic case workflow.

## Boundaries

The PCAP guest analyzer only invokes:

- `capinfos <pcap>`
- `zeek readpcap <pcap> <temporary-output-dir>`

It rejects PCAP paths outside `/cases` and avoids mounting disk images or
writing into evidence directories.

The disk guest analyzer only invokes:

- `ewfinfo <e01>`
- `mmls <e01>`
- `fsstat -o <selected-ntfs-offset> <e01>`
- `fls -r -o <selected-ntfs-offset> -p <e01>`

It hashes EWF segments before and after triage and does not mount the image.

The Autoruns guest analyzer uses Python ZIP and CSV parsing only. It rejects
ZIP paths outside `/cases`, requires exactly one CSV member, and hashes the ZIP
before and after decoding.

The protected registry guest analyzer extracts only `Protected/software` and
`Protected/system` from a ZIP below `/cases` and invokes:

- `rip.pl -r <software-hive> -p run`
- `rip.pl -r <system-hive> -p services`

It hashes the ZIP before and after analysis and preserves plugin output instead
of returning raw hive content to the model.

The UserAssist guest analyzer extracts only exported `NTUSER.DAT` members under
`Users/<profile>/` from a ZIP below `/cases` and invokes:

- `rip.pl -r <ntuser-hive> -p userassist`

It hashes the ZIP before and after analysis and preserves timestamped execution
context plus raw plugin output. UserAssist strengthens execution review when it
correlates with another artifact source; it is not a malware verdict.

The memory guest analyzer only invokes:

- `strings -a -n 6 <memory-image>`
- `strings -a -el -n 6 <memory-image>`

It requires explicit search terms, hashes the memory image before and after
analysis, and preserves matching lines only. It does not claim process
injection, socket ownership, or malware execution from strings alone.

## CLI Run

Create and validate a new case plan:

```powershell
.\.venv\Scripts\findevil-sift.exe init-case-plan `
  '.\cases\acme-incident.json' `
  --case-id 'acme-incident' `
  --case-name 'ACME Incident'

.\.venv\Scripts\findevil-sift.exe validate-case-plan `
  '.\cases\acme-incident.json'
```

Inventory a case root and draft a plan:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift.exe discover-case `
  '/cases/acme' `
  --output-dir '.\artifacts\acme-discovery' `
  --plan-output '.\cases\acme-discovered.json' `
  --case-id 'acme-discovered' `
  --case-name 'ACME Discovered Case'
```

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
$env:PYTHONPATH='src'
python -m findevil_sift.cli pcap-triage `
  '/cases/R&M/case001-pcap/case001.pcap' `
  --output-dir '.\artifacts\rm-case001-pcap'
```

Run the Autoruns lane against the current DC export:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift.exe autoruns-triage `
  '/cases/R&M/DC/DC01-autorunsc.zip' `
  --output-dir '.\artifacts\rm-dc-autoruns'
```

Run a case plan:

```powershell
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift.exe run-case `
  '.\cases\rm-stolen-szechuan-sauce.json' `
  --output-dir '.\artifacts\sample-case'
```

Workflow outputs include:

- `execution-log.json` with lane start, validation, bounded retry, evidence
  degradation, correlation, and completion events.
- `execution-report.md` with a human-readable execution trace.
- Lane bundles and validation JSON for lanes with benchmark manifests.
- Correlation JSON and Markdown when the plan contains current correlation
  inputs.
- `claims/claim-ledger.json` and `claims/claim-ledger.md` when correlation
  exists, with claim status labels and summary paths for review.
- `quality/quality-review.json` and `quality/quality-review.md` when claims
  exist, with a capped autonomous promotion review trace that blocks candidate
  and volatile claims from promotion.
- `claim-accuracy/claim-accuracy.json` and `claim-accuracy/claim-accuracy.md`
  when a labeled plan provides a claim-accuracy manifest, scoring expected
  promoted claim types, rejected unsupported claim types, misses, and unsafe
  promotions.
- `dossier/case-dossier.json` and `dossier/case-dossier.md` when a plan opts
  into a scenario profile.
- `executive/executive-report.md` and `executive/executive-summary.json` for
  leadership-facing status, triage signals, caveats, and next actions.
- `run-manifest.json` at the workflow output root with relative-path SHA-256
  digests for emitted files and an optional export signature.

Set `FINDEVIL_RUN_MANIFEST_KEY` before `run-case` when a bundle may leave the
workstation. The workflow adds an HMAC-SHA256 signature to `run-manifest.json`;
`FINDEVIL_RUN_MANIFEST_KEY_ID` can label the local export key without writing
the key into a case plan or output bundle. Verify hashes and any signature with:

```powershell
$env:FINDEVIL_RUN_MANIFEST_KEY='<local-export-key>'
.\.venv\Scripts\findevil-sift.exe verify-run-manifest `
  '.\artifacts\sample-case\run-manifest.json'
```

Unsigned manifests still verify file hashes. Signed manifests fail verification
until the same signing key is present in the verification environment.

## MCP Run

Install the project into a virtual environment, then expose the stdio server:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
$env:SIFT_GUEST_PASSWORD='<guest-password>'
.\.venv\Scripts\findevil-sift-mcp.exe
```

The MCP server exposes:

- `sift_pcap_policy`
- `sift_pcap_triage`
- `sift_disk_policy`
- `sift_disk_triage`
- `sift_autoruns_policy`
- `sift_autoruns_triage`
- `sift_registry_policy`
- `sift_registry_triage`
- `sift_userassist_policy`
- `sift_userassist_triage`
- `sift_memory_policy`
- `sift_memory_triage`
- `sift_case_inventory_policy`
- `sift_case_inventory`
- `sift_case_correlation`

The triage tool writes beneath `artifacts/mcp` by default. Set
`FINDEVIL_OUTPUT_ROOT` to change that controlled host output root.

## Benchmark Run

Validate the R&M case triage output against the first benchmark manifest:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-pcap-summary `
  '.\artifacts\rm-case001-pcap\summary.json' `
  '.\benchmarks\rm-case001-pcap.json' `
  --output '.\artifacts\rm-case001-pcap\validation.json'
```

Validate the DC disk lane:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-disk-summary `
  '.\artifacts\rm-dc-disk-v2\summary.json' `
  '.\benchmarks\rm-dc-disk.json' `
  --output '.\artifacts\rm-dc-disk-v2\validation.json'
```

Validate the DC Autoruns lane:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-autoruns-summary `
  '.\artifacts\rm-dc-autoruns\summary.json' `
  '.\benchmarks\rm-dc-autoruns.json' `
  --output '.\artifacts\rm-dc-autoruns\validation.json'
```

Validate the protected registry lane:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-registry-summary `
  '.\artifacts\rm-dc-registry\summary.json' `
  '.\benchmarks\rm-dc-registry.json' `
  --output '.\artifacts\rm-dc-registry\validation.json'
```

Validate the bounded DC memory lane:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-memory-summary `
  '.\artifacts\rm-dc-memory\summary.json' `
  '.\benchmarks\rm-dc-memory.json' `
  --output '.\artifacts\rm-dc-memory\validation.json'
```

Validate the exported UserAssist lane:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-userassist-summary `
  '.\artifacts\rm-dc-userassist\summary.json' `
  '.\benchmarks\rm-dc-userassist.json' `
  --output '.\artifacts\rm-dc-userassist\validation.json'
```

Correlate preserved PCAP, disk, Autoruns, registry, and memory summaries:

```powershell
.\.venv\Scripts\findevil-sift.exe correlate-case `
  '.\artifacts\rm-case001-pcap\summary.json' `
  '.\artifacts\rm-dc-disk-v2\summary.json' `
  --autoruns-summary '.\artifacts\rm-dc-autoruns\summary.json' `
  --registry-summary '.\artifacts\rm-dc-registry\summary.json' `
  --userassist-summary '.\artifacts\rm-dc-userassist\summary.json' `
  --memory-summary '.\artifacts\rm-dc-memory\summary.json' `
  --output-dir '.\artifacts\rm-case-correlation'
```
