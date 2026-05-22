# Dataset Note: R&M Case 001 PCAP

## Local Evidence

- Guest path: `/cases/R&M/case001-pcap/case001.pcap`
- Evidence type: PCAPNG capture
- SHA-256: `09abf49efea1852e047987d92907704d47f36d75f6c8056e2cafa6cc027791cb`
- Capture window reported by SIFT `capinfos`:
  - First packet: `2020-09-18 21:58:07.470323`
  - Last packet: `2020-09-19 05:38:57.828520`

The evidence remains in the SIFT VM under `/cases`; it is not copied into this
repository.

## Benchmark Role

This case is the first regression fixture for the PCAP product lane. The
benchmark manifest records:

- The expected evidence hash.
- Required Zeek output families.
- Minimum output counts to catch parser or tool regressions.
- Known pivots currently observed in the PCAP triage summary, including the
  private HTTP host pivot for `o.ss2.us`.

The manifest validates extraction and integrity behavior. It is not yet a full
malicious-activity ground-truth label set.

