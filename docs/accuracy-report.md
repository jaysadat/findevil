# Prototype Accuracy Report

## Scope

This report covers the live R&M regression fixtures currently exercised by the
prototype:

- PCAP: `/cases/R&M/case001-pcap/case001.pcap`
- DC disk image: `/cases/R&M/DC/Combined/image.E01`
- DC Autoruns export: `/cases/R&M/DC/DC01-autorunsc.zip`
- DC protected-files export: `/cases/R&M/DC/DC01-ProtectedFiles.zip`
- DC exported UserAssist hives from the protected-files ZIP
- DC memory image: `/cases/R&M/DC/Combined/citadeldc01.mem`

## Current Result

The live regression runs on May 21-22, 2026 UTC produced:

- PCAP evidence hash continuity, 27 Zeek log families, and benchmark validation
  score `18 / 18`, including an HTTP `coreupdater.exe` delivery pivot and SSL
  protocol-violation pivot toward `203.78.103.109`.
- Disk segment hash continuity, selected NTFS offset `718848`, and benchmark
  validation score `16 / 16`.
- Autoruns ZIP hash continuity, 902 parsed rows, and 3 high-signal persistence
  pivots from the DC export: `coreupdater`, `ad_driver`, and `coreupdate`.
- Protected registry ZIP hash continuity, 3 SOFTWARE Run entries, 453 SYSTEM
  service entries, two persistence pivots: `coreupdate` and `coreupdater`, and
  a decoded nested PowerShell payload chain referenced from SOFTWARE.
- UserAssist ZIP hash continuity, 2 exported user hives, 16 timestamped
  execution entries, and preserved execution context for `coreupdater.exe`,
  PowerShell, and `cmd.exe`.
- DC memory hash continuity and benchmark validation score `7 / 7` for bounded
  strings pivots covering `coreupdater`, delivery IP `194.61.24.102`, callback
  IP `203.78.103.109`, and hidden registry markers `9sEoCawv` and `45SVAG2o`.
- Case correlation that marks `coreupdate` and `coreupdater` as corroborated
  across Autoruns and protected registry sources while carrying memory string
  pivots as volatile follow-up support.
- Correlation that aligns the `coreupdater` host pivot with timestamped
  Administrator UserAssist execution context from the exported user hive.
- A case workflow execution log that records the benchmark scores and the
  decision to use the exported Autoruns path after the disk metadata reports
  corruption.
- A labeled claim-accuracy review that expects supported domain context and
  corroborated persistence to promote, expects candidate network and Autoruns
  pivots plus volatile memory pivots to remain blocked, and forbids candidate or
  volatile statuses from reaching the executive layer.

## Benchmark Checks

The R&M PCAP manifest validates:

- Expected evidence hash and unchanged evidence state.
- Required Zeek logs for network, file, RDP, and notice pivots.
- Minimum parsed record counts for connection, DNS, HTTP, and TLS logs.
- Known extracted pivots observed in this case, including:
  - Private HTTP host pivot `o.ss2.us`.
  - Extracted MIME pivots `application/x-dosexec` and `application/zip`.
  - HTTP executable delivery of `/coreupdater.exe` from `194.61.24.102` to
    `10.42.85.10`.
  - An SSL protocol-violation destination pivot for `203.78.103.109`.

The DC disk manifest validates EWF segment hashes, NTFS offset selection, case
metadata, and artifact inventory pivots for SYSVOL, Group Policy registry files,
NTDS, hives, Amcache, and PowerShell-adjacent paths.

The DC Autoruns manifest validates the ZIP hash, exported CSV member, row-count
floors, and the three current high-signal persistence pivots.

The protected registry manifest validates the ZIP hash, required SOFTWARE and
SYSTEM hive members, RegRipper Run/service count floors, the two current
registry persistence pivots, and indicators from the decoded registry payload
chain.

The UserAssist manifest validates the protected export ZIP hash, exported
Administrator and Default NTUSER members, entry-count floors, and timestamped
execution entries for `coreupdater.exe`, `powershell.exe`, and `cmd.exe`.

The DC memory manifest validates the memory SHA-256, unchanged evidence state,
and minimum hit counts for five explicit case pivot terms.

The R&M scenario profile validates the evidence-integrity set, delivery pivot,
callback-network hint, `c137.local` domain context, and cross-artifact
persistence corroboration for `coreupdate` and `coreupdater`. It also checks
that the expected volatile pivot terms are present in the bounded memory lane.

The R&M claim-accuracy manifest validates reporting behavior after correlation:

- Expected promoted claim types: `domain_hint_match`,
  `persistence_corroboration`, and `userassist_execution_corroboration`.
- Expected blocked claim types: `dc_network_pivot`,
  `autoruns_persistence_pivot`, and `memory_string_pivot`.
- Forbidden promoted statuses: `candidate` and `volatile_pivot`.

## Negative Controls

The unit suite now exercises negative reporting and constraint cases:

- Case-plan validation rejects guest evidence paths outside `/cases`.
- Case-plan validation rejects workflow output directory traversal such as
  `../outside`.
- Guest-analyzer validators reject evidence or inventory roots outside `/cases`.
- The PCAP guest summary preserves before/after SHA-256 drift as changed
  evidence instead of reporting the evidence as unchanged.
- Claim review keeps candidate and volatile claim classes out of promoted
  executive signals.
- Claim-accuracy scoring fails an unsafe candidate promotion and counts it as
  both an unexpected promoted class and an unsafe promotion.

## Accuracy Limits

The current benchmark suite demonstrates repeatable extraction, integrity
behavior, and pivot surfacing. It does not yet score incident conclusions
against a full malicious-activity ground-truth timeline. Confirmed findings must
still be tied to preserved outputs or later analyst review.

## Next Accuracy Upgrade

The next evaluation slice should add labeled expected findings from deeper R&M
host artifacts or memory-forensics tooling and move beyond current claim-type
scoring to incident-level finding scoring:

- Confirmed true positives.
- False positives.
- Missed expected findings.
- Unsupported claims rejected by the report layer.
