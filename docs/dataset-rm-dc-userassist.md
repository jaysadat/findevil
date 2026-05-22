# Dataset Note: R&M DC UserAssist Export

## Local Evidence

- Guest ZIP: `/cases/R&M/DC/DC01-ProtectedFiles.zip`
- ZIP SHA-256:
  `b1f3d42a9629dc25521685f296959c4c6d36bbf2efd355c127cb49171c372424`
- Exported user hives used by the sample benchmark:
  `Users/Administrator/NTUSER.DAT` and `Users/Default/NTUSER.DAT`

The UserAssist lane reuses the protected-files export only for exported
`NTUSER.DAT` members under `Users/<profile>/`. It hashes the ZIP before and
after analysis, runs RegRipper `userassist` on each extracted hive in a
temporary guest job directory, and preserves the plugin output.

## Benchmark Role

The fixture validates:

- The protected-files ZIP hash and unchanged evidence state.
- Exported Administrator and Default user hive members.
- UserAssist profile and timestamped execution-entry floors.
- Timestamped execution context for `coreupdater.exe`, `powershell.exe`, and
  `cmd.exe`.

UserAssist gives the case correlation layer a preserved user execution signal
to compare with persistence pivots. It does not classify an entry as malware by
itself.
