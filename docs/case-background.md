# Case Background: The Stolen Szechuan Sauce

## Evidence Set

The R&M evidence loaded in SIFT belongs to DFIR Madness Case 001, The Stolen
Szechuan Sauce. The published case intentionally provides multiple acquisition
views for a training investigation:

| Local Artifact | Case Role |
| --- | --- |
| `case001.pcap` | Network capture for delivery, callback, topology, RDP, and exfiltration pivots. |
| DC E01 | Domain Controller disk image for host file-system and timeline context. |
| DC Autoruns ZIP | Acquisition-time startup surface for fast persistence triage. |
| DC Protected Files ZIP | Protected hive, user-hive, and NTDS export; this workflow uses SOFTWARE/SYSTEM for registry corroboration and NTUSER UserAssist entries for execution context. |
| DC memory | Volatile host evidence used here for bounded string corroboration. |
| DC pagefile | Additional volatile spill evidence held for later depth. |

The published brief says the files of concern were stored on the Domain
Controller file server, names the victim network as `10.42` space, and notes
that Colorado September local time matters when interpreting timestamps.

## Published Alignment Pivots

The current production demo does not grade itself only on parser output. Its R&M
profile checks extracted pivots against the case trail:

- The PCAP lane should surface HTTP executable delivery of
  `/coreupdater.exe` from `194.61.24.102` to the Domain Controller host
  `10.42.85.10`.
- The PCAP lane should preserve a callback-network hint involving
  `203.78.103.109`.
- Autoruns should surface `coreupdater.exe` in System32 as a persistence pivot.
- Protected registry hives should corroborate `coreupdate` in Run and
  `coreupdater` as a service.
- Exported UserAssist entries should preserve timestamped Administrator
  execution context for `coreupdater.exe`.
- The memory lane should preserve volatile hits for `coreupdater`, both network
  IP pivots, and the hidden SOFTWARE key/value markers referenced by the Run
  command.

## Product Interpretation

The case dossier marks these as scenario-alignment checks and pivots. Reports
keep raw Zeek logs, RegRipper outputs, UserAssist output, decoded Autoruns CSV,
bounded memory string hits, and evidence hashes so an analyst can promote a
pivot to a finding only after reviewing preserved supporting output.

## Source Trail

- DFIR Madness case brief:
  `https://dfirmadness.com/the-stolen-szechuan-sauce/`
- DFIR Madness PCAP analysis:
  `https://dfirmadness.com/case-001-pcap-analysis/`
- DFIR Madness Autoruns analysis:
  `https://dfirmadness.com/case-001-autoruns-analysis/`
- DFIR Madness memory analysis:
  `https://dfirmadness.com/case-001-memory-analysis/`
- DFIR Madness disk triage analysis:
  `https://dfirmadness.com/triage-disk-analysis-case-001/`
