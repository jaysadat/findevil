# Dataset Note: R&M DC Memory

## Artifact

- Guest path: `/cases/R&M/DC/Combined/citadeldc01.mem`
- Benchmark manifest: `benchmarks/rm-dc-memory.json`
- Current role: bounded volatile pivot corroboration for the R&M case profile.

## Current Lane

The memory lane records the memory-image SHA-256 before and after analysis,
scans ASCII and UTF-16LE strings with explicit search terms, and preserves only
matching string lines in `memory-string-hits.zip`.

The current profile terms are:

- `coreupdater`
- `194.61.24.102`
- `203.78.103.109`
- `9sEoCawv`
- `45SVAG2o`

These terms bridge payload, network, and registry pivots already surfaced by
the PCAP and protected-registry lanes.

## Boundary

String hits can corroborate analyst pivots, but they do not by themselves prove
process injection, execution timing, or socket ownership. Those claims need a
deeper memory-forensics lane and preserved plugin output.
