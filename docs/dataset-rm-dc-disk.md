# Dataset Note: R&M DC Disk Image

## Local Evidence

- Guest primary segment: `/cases/R&M/DC/Combined/image.E01`
- Companion EWF segment: `/cases/R&M/DC/Combined/20200918_0347_CDrive.E02`
- EWF case number: `20200918-001`
- EWF description: `CITADEL-DC01`
- Selected NTFS partition offset: `718848` sectors

The EWF metadata reports `Is corrupted: yes`. The product keeps that caveat in
the disk report and does not promote disk pivots to incident conclusions without
later evidence review.

## Segment Hashes

| Segment | SHA-256 |
| --- | --- |
| `image.E01` | `c0c8fe58dcdb65f6574cb63b34f086856087cfaf06872ed702a4c0c264446bac` |
| `20200918_0347_CDrive.E02` | `73f87df9de0fa9ed41c6fdc360f0e15c3d13955e7fd24f5e59a5b2e282d6b384` |

## Benchmark Role

This case is the first regression fixture for mount-free disk triage. The
manifest validates:

- EWF segment hashes before and after triage.
- Automatic selection of the large NTFS partition.
- EWF case metadata.
- Domain-controller-relevant pivots in the recursive Sleuth Kit listing,
  including `NTDS`, ESE logs, SYSVOL paths, Group Policy registry policy files,
  Amcache, NTUSER hives, and PowerShell-adjacent paths.

The fixture measures inventory and integrity behavior. It does not yet parse
the NTDS database, registry hives, or Amcache content.

