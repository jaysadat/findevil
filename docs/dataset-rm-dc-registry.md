# Dataset Note: R&M DC Protected Registry Export

## Local Evidence

- Guest ZIP: `/cases/R&M/DC/DC01-ProtectedFiles.zip`
- ZIP SHA-256:
  `b1f3d42a9629dc25521685f296959c4c6d36bbf2efd355c127cb49171c372424`
- Required hive members: `Protected/software` and `Protected/system`

The registry lane uses only the exported hives in the ZIP. It extracts SOFTWARE
and SYSTEM into a temporary guest job directory, runs RegRipper `run` and
`services`, hashes the ZIP before and after analysis, and preserves the plugin
outputs.

## Benchmark Role

The fixture validates:

- The protected-files ZIP hash and unchanged evidence state.
- Required SOFTWARE and SYSTEM hive members.
- Minimum Run-key and service-entry counts from RegRipper output.
- Registry persistence pivots for `coreupdate` and `coreupdater`.

The Run-key and service pivots corroborate the same persistence names surfaced
by the Autoruns export, giving correlation a second host artifact source.
The sibling UserAssist lane reuses the same ZIP only for exported NTUSER hives;
its dataset note is kept separate because it answers a different execution
context question.
