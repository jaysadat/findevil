# Dataset Note: R&M DC Autoruns Export

## Local Evidence

- Guest ZIP: `/cases/R&M/DC/DC01-autorunsc.zip`
- ZIP SHA-256:
  `2855472b2af6d44bfe00cc7a62c3b467b6aa5a138ba6a4af2600a9c5b58c054f`
- Exported CSV member: `autorunsc-citadel-dc01.csv`

The export stays below `/cases` in the SIFT guest. The Autoruns lane decodes
the UTF-16 CSV from the ZIP, hashes the ZIP before and after analysis, and keeps
the decoded CSV in the preserved output bundle.

## Benchmark Role

The fixture validates:

- The expected ZIP hash and unchanged evidence state.
- The expected Autoruns CSV member.
- Minimum parsed and enabled row counts.
- High-signal persistence pivots observed in the current export:
  `coreupdater`, `ad_driver`, and `coreupdate`.

The high-signal layer is narrower than the full review-candidate list. It
surfaces unsigned service or driver persistence, writable execution paths, and
payload-like script launch strings as follow-up pivots. It does not claim those
rows alone prove compromise.
