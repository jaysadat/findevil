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

The example points at placeholder folders for a local DFIR reference corpus.
Keep licensed PDFs and local indexes out of the public repository. Ignored
`knowledge/corpus.json` can describe an operator-specific corpus when paths
differ.

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

## Guidance Index

Build a bounded lexical index from the catalog, then query guidance hits:

```powershell
.\.venv\Scripts\findevil-sift.exe index-knowledge `
  '.\artifacts\knowledge-catalog\knowledge-catalog.json' `
  --output-dir '.\knowledge\indexes\operator-dfir-guidance'
.\.venv\Scripts\findevil-sift.exe query-knowledge `
  '.\knowledge\indexes\operator-dfir-guidance\knowledge-index.json' `
  --query 'memory process persistence next actions' `
  --output-dir '.\artifacts\knowledge-guidance'
```

Indexing re-checks each cataloged source hash before PDF, text, or Markdown
extraction. The index caps extracted characters per source and returns bounded
lexical chunks with source label, relative path, location, chunk ID, and source
SHA-256. It is a local guidance retrieval layer rather than an evidence lane:
the query output repeats the boundary and cannot promote a case claim.

## Guidance Policy And Evaluation

Host config `operator_policy.approved_knowledge_index_roots` can constrain
`query-knowledge` and guidance evaluation to selected local index roots. Use an
evaluation manifest before guidance starts drafting plans or next actions:

```powershell
.\.venv\Scripts\findevil-sift.exe validate-knowledge-guidance `
  '.\knowledge\indexes\operator-dfir-guidance\knowledge-index.json' `
  '.\benchmarks\guidance-evaluation.example.json' `
  --output '.\artifacts\knowledge-guidance-evaluation.json'
```

The example fixture expects the selected SANS memory and SIFT cheat sheets from
`knowledge/corpus.example.json`. Evaluation checks whether expected relative
source paths appear within each bounded query result; it measures retrieval
coverage, not forensic truth.

## Draft Planning

After an index is approved and evaluated, guidance can write a review-only
planning artifact:

```powershell
.\.venv\Scripts\findevil-sift.exe draft-guidance-plan `
  '.\knowledge\indexes\operator-dfir-guidance\knowledge-index.json' `
  --case-id 'acme-incident' `
  --case-name 'ACME Incident' `
  --context 'memory process persistence review for suspect.exe and network pivots' `
  --output-dir '.\artifacts\acme-guidance-plan'
```

The output is `guidance-plan-draft.json` and `guidance-plan-draft.md`. It can
suggest lanes, possible memory terms, and next actions, but it is deliberately
not a case plan and does not write into `cases/`. An analyst must review
evidence inventory, author or edit a case plan, and run `validate-case-plan`
before any SIFT workflow run.
