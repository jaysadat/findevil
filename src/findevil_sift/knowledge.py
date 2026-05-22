from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pypdf import PdfReader

SUPPORTED_SUFFIXES = {".pdf", ".txt", ".md"}
INDEX_SCHEMA = "findevil.knowledge_index.v1"
GUIDANCE_SCHEMA = "findevil.knowledge_guidance.v1"
CHUNK_CHARS = 1400
CHUNK_OVERLAP_CHARS = 200
MAX_SOURCE_CHARS = 250_000
MAX_QUERY_HITS = 10
EVIDENCE_BOUNDARY = (
    "Knowledge sources are reference guidance only. They may guide case-plan "
    "drafting and analyst next actions, but they do not support forensic claims."
)


def load_and_validate_knowledge_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = manifest_path.resolve(strict=True)
    try:
        manifest = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {}, validation_result(
            resolved,
            [check("json", False, "valid JSON object", f"{exc.msg} at line {exc.lineno}")],
        )
    return manifest, validate_knowledge_manifest(manifest, resolved)


def validate_knowledge_manifest(manifest: Any, manifest_path: Path) -> dict[str, Any]:
    checks = [check("manifest_object", isinstance(manifest, dict), "JSON object", type(manifest).__name__)]
    if not isinstance(manifest, dict):
        return validation_result(manifest_path, checks)

    roots = manifest.get("roots")
    checks.extend(
        [
            check(
                "knowledge_id",
                isinstance(manifest.get("knowledge_id"), str) and bool(manifest["knowledge_id"].strip()),
                "non-empty knowledge corpus identifier",
                manifest.get("knowledge_id"),
            ),
            check("roots", isinstance(roots, list) and bool(roots), "non-empty root list", roots),
        ]
    )
    if isinstance(roots, list):
        for index, root in enumerate(roots, start=1):
            checks.extend(validate_root(root, index))
    return validation_result(manifest_path, checks)


def validate_root(root: Any, index: int) -> list[dict[str, Any]]:
    prefix = f"root:{index}"
    checks = [
        check(f"{prefix}:object", isinstance(root, dict), "root object", type(root).__name__),
    ]
    if not isinstance(root, dict):
        return checks
    include = root.get("include", ["**/*.pdf"])
    allowed_suffixes = root.get("allowed_suffixes", sorted(SUPPORTED_SUFFIXES))
    checks.extend(
        [
            check(
                f"{prefix}:path",
                isinstance(root.get("path"), str) and bool(root["path"].strip()),
                "non-empty local directory path",
                root.get("path"),
            ),
            check(
                f"{prefix}:label",
                isinstance(root.get("label"), str) and bool(root["label"].strip()),
                "non-empty display label",
                root.get("label"),
            ),
            check(
                f"{prefix}:include",
                isinstance(include, list)
                and bool(include)
                and all(isinstance(item, str) and bool(item.strip()) for item in include),
                "non-empty glob list",
                include,
            ),
            check(
                f"{prefix}:allowed_suffixes",
                isinstance(allowed_suffixes, list)
                and bool(allowed_suffixes)
                and all(isinstance(item, str) and item.lower() in SUPPORTED_SUFFIXES for item in allowed_suffixes),
                f"suffix list from {', '.join(sorted(SUPPORTED_SUFFIXES))}",
                allowed_suffixes,
            ),
        ]
    )
    return checks


def catalog_knowledge(manifest_path: Path, output_dir: Path) -> dict[str, str | int]:
    manifest, validation = load_and_validate_knowledge_manifest(manifest_path)
    if not validation["passed"]:
        raise ValueError(f"knowledge manifest validation failed: {validation}")

    output_dir.mkdir(parents=True, exist_ok=True)
    sources = []
    missing_roots = []
    for root in manifest["roots"]:
        root_path = Path(root["path"]).expanduser().resolve()
        if not root_path.is_dir():
            missing_roots.append({"label": root["label"], "path": str(root_path)})
            continue
        allowed = {suffix.lower() for suffix in root.get("allowed_suffixes", SUPPORTED_SUFFIXES)}
        for path in iter_root_files(root_path, root.get("include", ["**/*.pdf"]), allowed):
            sources.append(catalog_source(path, root_path, root["label"]))

    catalog = {
        "generated_at": utc_now(),
        "knowledge_id": manifest["knowledge_id"],
        "manifest_path": str(manifest_path.resolve()),
        "boundary": EVIDENCE_BOUNDARY,
        "source_count": len(sources),
        "missing_roots": missing_roots,
        "sources": sources,
    }
    summary_path = output_dir / "knowledge-catalog.json"
    report_path = output_dir / "knowledge-catalog.md"
    summary_path.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_knowledge_catalog_report(catalog), encoding="utf-8")
    return {
        "status": "ok" if not missing_roots else "partial",
        "source_count": len(sources),
        "missing_root_count": len(missing_roots),
        "summary": str(summary_path),
        "report": str(report_path),
    }


def iter_root_files(root: Path, patterns: list[str], allowed_suffixes: set[str]) -> list[Path]:
    matches = {
        path.resolve()
        for pattern in patterns
        for path in root.glob(pattern)
        if path.is_file() and path.suffix.lower() in allowed_suffixes
    }
    return sorted(matches)


def catalog_source(path: Path, root: Path, label: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "label": label,
        "path": str(path),
        "relative_path": str(path.relative_to(root)),
        "suffix": path.suffix.lower(),
        "size_bytes": stat.st_size,
        "sha256": sha256_file(path),
    }


def index_knowledge(catalog_path: Path, output_dir: Path) -> dict[str, str | int]:
    path = catalog_path.resolve(strict=True)
    catalog = json.loads(path.read_text(encoding="utf-8"))
    validate_catalog_for_index(catalog)
    output_dir.mkdir(parents=True, exist_ok=True)
    chunks = []
    skipped_sources = []
    for source in catalog["sources"]:
        try:
            chunks.extend(index_source(source))
        except Exception as exc:
            skipped_sources.append(
                {
                    "label": source.get("label"),
                    "relative_path": source.get("relative_path"),
                    "reason": str(exc),
                }
            )
    index = {
        "schema": INDEX_SCHEMA,
        "generated_at": utc_now(),
        "knowledge_id": catalog["knowledge_id"],
        "catalog_path": str(path),
        "boundary": EVIDENCE_BOUNDARY,
        "limits": {
            "chunk_chars": CHUNK_CHARS,
            "chunk_overlap_chars": CHUNK_OVERLAP_CHARS,
            "max_source_chars": MAX_SOURCE_CHARS,
            "max_query_hits": MAX_QUERY_HITS,
        },
        "source_count": len(catalog["sources"]),
        "indexed_source_count": len({item["source_sha256"] for item in chunks}),
        "chunk_count": len(chunks),
        "skipped_sources": skipped_sources,
        "chunks": chunks,
    }
    summary_path = output_dir / "knowledge-index.json"
    report_path = output_dir / "knowledge-index.md"
    summary_path.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_knowledge_index_report(index), encoding="utf-8")
    return {
        "status": "ok" if not skipped_sources else "partial",
        "source_count": index["source_count"],
        "indexed_source_count": index["indexed_source_count"],
        "chunk_count": len(chunks),
        "skipped_source_count": len(skipped_sources),
        "summary": str(summary_path),
        "report": str(report_path),
    }


def query_knowledge(
    index_path: Path,
    query: str,
    output_dir: Path,
    *,
    limit: int = 5,
) -> dict[str, str | int]:
    if limit < 1 or limit > MAX_QUERY_HITS:
        raise ValueError(f"knowledge query limit must be between 1 and {MAX_QUERY_HITS}")
    cleaned_query = query.strip()
    terms = query_terms(cleaned_query)
    if not terms:
        raise ValueError("knowledge query must contain searchable terms")
    path = index_path.resolve(strict=True)
    index = json.loads(path.read_text(encoding="utf-8"))
    validate_index_for_query(index)
    ranked = sorted(
        (score_chunk(chunk, terms) for chunk in index["chunks"]),
        key=lambda item: (-item["score"], item["label"], item["relative_path"], item["chunk_id"]),
    )
    hits = [item for item in ranked if item["score"] > 0][:limit]
    guidance = {
        "schema": GUIDANCE_SCHEMA,
        "generated_at": utc_now(),
        "knowledge_id": index["knowledge_id"],
        "index_path": str(path),
        "boundary": EVIDENCE_BOUNDARY,
        "query": cleaned_query,
        "terms": terms,
        "hit_count": len(hits),
        "hits": hits,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "knowledge-guidance.json"
    report_path = output_dir / "knowledge-guidance.md"
    summary_path.write_text(json.dumps(guidance, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_knowledge_guidance_report(guidance), encoding="utf-8")
    return {
        "status": "ok",
        "hit_count": len(hits),
        "summary": str(summary_path),
        "report": str(report_path),
    }


def validate_catalog_for_index(catalog: Any) -> None:
    if not isinstance(catalog, dict) or not isinstance(catalog.get("sources"), list):
        raise ValueError("knowledge catalog must contain a source list")
    if catalog.get("boundary") != EVIDENCE_BOUNDARY:
        raise ValueError("knowledge catalog boundary is missing or unsupported")
    if not isinstance(catalog.get("knowledge_id"), str) or not catalog["knowledge_id"].strip():
        raise ValueError("knowledge catalog must contain knowledge_id")


def validate_index_for_query(index: Any) -> None:
    if not isinstance(index, dict) or index.get("schema") != INDEX_SCHEMA:
        raise ValueError("knowledge index schema is missing or unsupported")
    if index.get("boundary") != EVIDENCE_BOUNDARY:
        raise ValueError("knowledge index boundary is missing or unsupported")
    if not isinstance(index.get("chunks"), list):
        raise ValueError("knowledge index must contain chunks")


def index_source(source: dict[str, Any]) -> list[dict[str, Any]]:
    path = Path(source["path"]).expanduser().resolve(strict=True)
    if sha256_file(path) != source.get("sha256"):
        raise ValueError("cataloged source SHA-256 changed before indexing")
    units = extract_source_units(path, source["suffix"])
    chunks = []
    chunk_index = 0
    remaining_chars = MAX_SOURCE_CHARS
    for location, text in units:
        if remaining_chars <= 0:
            break
        bounded = normalize_text(text)[:remaining_chars]
        remaining_chars -= len(bounded)
        for chunk_text in chunk_text_units(bounded):
            chunk_index += 1
            chunks.append(
                {
                    "chunk_id": f"{source['sha256'][:12]}-{chunk_index:04d}",
                    "label": source["label"],
                    "relative_path": source["relative_path"],
                    "suffix": source["suffix"],
                    "source_sha256": source["sha256"],
                    "location": location,
                    "text": chunk_text,
                }
            )
    return chunks


def extract_source_units(path: Path, suffix: str) -> list[tuple[str, str]]:
    if suffix in {".md", ".txt"}:
        return [("document", path.read_text(encoding="utf-8", errors="replace"))]
    if suffix == ".pdf":
        reader = PdfReader(path)
        if reader.is_encrypted:
            raise ValueError("encrypted PDF cannot be indexed")
        return [
            (f"page {index}", page.extract_text() or "")
            for index, page in enumerate(reader.pages, start=1)
        ]
    raise ValueError(f"unsupported knowledge source suffix: {suffix}")


def chunk_text_units(text: str) -> list[str]:
    if not text:
        return []
    step = CHUNK_CHARS - CHUNK_OVERLAP_CHARS
    return [text[start : start + CHUNK_CHARS] for start in range(0, len(text), step)]


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def query_terms(query: str) -> list[str]:
    return sorted({term.lower() for term in re.findall(r"[A-Za-z0-9_.-]{2,}", query)})


def score_chunk(chunk: dict[str, Any], terms: list[str]) -> dict[str, Any]:
    text = chunk["text"]
    folded = text.lower()
    matches = {term: folded.count(term) for term in terms if term in folded}
    return {
        "score": sum(matches.values()),
        "matched_terms": matches,
        "chunk_id": chunk["chunk_id"],
        "label": chunk["label"],
        "relative_path": chunk["relative_path"],
        "source_sha256": chunk["source_sha256"],
        "location": chunk["location"],
        "text": text,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def render_knowledge_catalog_report(catalog: dict[str, Any]) -> str:
    roots = "\n".join(
        f"- `{item['label']}`: `{item['path']}`"
        for item in catalog.get("missing_roots", [])
    )
    rows = "\n".join(
        f"| {item['label']} | `{item['relative_path']}` | {item['suffix']} | {item['size_bytes']} | `{item['sha256']}` |"
        for item in catalog["sources"]
    )
    return f"""# Find Evil Knowledge Catalog

Generated: {catalog["generated_at"]}

## Boundary

{catalog["boundary"]}

## Scope

- Knowledge ID: `{catalog["knowledge_id"]}`
- Sources cataloged: `{catalog["source_count"]}`

## Missing Roots

{roots or "- No configured roots were missing."}

## Sources

| Label | Relative path | Type | Bytes | SHA-256 |
| --- | --- | --- | --- | --- |
{rows or "| None | None | None | 0 | None |"}
"""


def render_knowledge_index_report(index: dict[str, Any]) -> str:
    skipped = "\n".join(
        f"- `{item['label']}/{item['relative_path']}`: {item['reason']}"
        for item in index["skipped_sources"]
    )
    return f"""# Find Evil Knowledge Index

Generated: {index["generated_at"]}

## Boundary

{index["boundary"]}

## Scope

- Knowledge ID: `{index["knowledge_id"]}`
- Catalog sources: `{index["source_count"]}`
- Indexed sources: `{index["indexed_source_count"]}`
- Text chunks: `{index["chunk_count"]}`
- Maximum extracted characters per source: `{index["limits"]["max_source_chars"]}`

## Skipped Sources

{skipped or "- No cataloged sources were skipped."}
"""


def render_knowledge_guidance_report(guidance: dict[str, Any]) -> str:
    hits = "\n\n".join(render_guidance_hit(index, hit) for index, hit in enumerate(guidance["hits"], start=1))
    return f"""# Find Evil Knowledge Guidance

Generated: {guidance["generated_at"]}

## Boundary

{guidance["boundary"]}

Guidance hits are operator references for review. Promote findings only from
case evidence lane outputs and preserved raw outputs.

## Query

- Knowledge ID: `{guidance["knowledge_id"]}`
- Query: `{guidance["query"]}`
- Hits returned: `{guidance["hit_count"]}`

## Hits

{hits or "No indexed guidance chunks matched the query."}
"""


def render_guidance_hit(index: int, hit: dict[str, Any]) -> str:
    terms = ", ".join(f"`{term}`={count}" for term, count in hit["matched_terms"].items())
    return f"""### {index}. {hit["relative_path"]}

- Source label: `{hit["label"]}`
- Location: `{hit["location"]}`
- Chunk ID: `{hit["chunk_id"]}`
- Source SHA-256: `{hit["source_sha256"]}`
- Lexical score: `{hit["score"]}`
- Matched terms: {terms or "None"}

> {hit["text"]}
"""


def validation_result(path: Path, checks: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(1 for item in checks if item["passed"])
    return {
        "generated_at": utc_now(),
        "manifest_path": str(path),
        "passed": passed == len(checks),
        "score": {"passed_checks": passed, "total_checks": len(checks)},
        "checks": checks,
        "boundary": EVIDENCE_BOUNDARY,
    }


def check(name: str, passed: bool, expected: Any, observed: Any) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "expected": expected, "observed": observed}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
