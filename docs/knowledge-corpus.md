# Knowledge Corpus

Find Evil SIFT keeps operator references separate from case evidence. PDFs,
text files, and Markdown runbooks can guide case-plan drafting, tool choice,
and analyst next actions, but they do not support forensic claims. Claim support
continues to come from lane summaries and preserved raw outputs.

## Local Manifest

Use `knowledge/corpus.example.json` as the public shape for a local corpus
manifest. A root names:

- A display label.
- A local directory path.
- Include globs.
- Allowed suffixes from `.pdf`, `.txt`, and `.md`.

The example points at selected folders from the older local
`E:\ai-cyber-assistant\data` corpus. Keep licensed PDFs and local indexes out
of the public repository. Ignored `knowledge/corpus.json` can describe an
operator-specific corpus when paths differ.

## Catalog

Validate and catalog a manifest:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-knowledge-manifest `
  '.\knowledge\corpus.example.json'
.\.venv\Scripts\findevil-sift.exe catalog-knowledge `
  '.\knowledge\corpus.example.json' `
  --output-dir '.\artifacts\knowledge-catalog'
```

The catalog writes:

- `knowledge-catalog.json` with source paths, relative paths, sizes, and
  SHA-256 values.
- `knowledge-catalog.md` with the same boundary and an operator-readable table.

This first step intentionally inventories approved local references without
adding embeddings or retrieval dependencies. A later retrieval layer should
consume the catalog boundary and keep generated guidance labeled separately
from evidence-backed reporting.
