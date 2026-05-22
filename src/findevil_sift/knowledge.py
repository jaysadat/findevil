from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUPPORTED_SUFFIXES = {".pdf", ".txt", ".md"}
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
        root_path = Path(root["path"]).expanduser()
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
