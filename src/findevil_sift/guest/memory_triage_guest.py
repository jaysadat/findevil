from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_SUFFIXES = {".mem", ".raw", ".bin"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--memory", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--term", action="append", required=True)
    args = parser.parse_args()

    memory_path = validate_memory_path(Path(args.memory))
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    hits_dir = output_dir / "memory-hits"
    hits_dir.mkdir(exist_ok=True)
    command_records: list[dict[str, Any]] = []

    before = hash_file(memory_path)
    ascii_hits = scan_strings(
        ["strings", "-a", "-n", "6", str(memory_path)],
        args.term,
        hits_dir / "ascii-hits.txt",
        "ascii",
        command_records,
    )
    utf16_hits = scan_strings(
        ["strings", "-a", "-el", "-n", "6", str(memory_path)],
        args.term,
        hits_dir / "utf16le-hits.txt",
        "utf16le",
        command_records,
    )
    after = hash_file(memory_path)

    summary = {
        "generated_at": utc_now(),
        "evidence": {
            "path": str(memory_path),
            "before_sha256": before["sha256"],
            "after_sha256": after["sha256"],
            "size_bytes": before["size_bytes"],
            "unchanged": before == after,
        },
        "commands": command_records,
        "memory": summarize_hits(args.term, ascii_hits, utf16_hits),
    }
    summary["observations"] = observations(summary)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    zip_outputs(hits_dir, output_dir / "memory-string-hits.zip")
    return 0


def validate_memory_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"memory evidence is not a file: {resolved}")
    if resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        raise ValueError(f"memory evidence must use one of {sorted(ALLOWED_SUFFIXES)}")
    if not str(resolved).startswith("/cases/"):
        raise ValueError("memory evidence must live below /cases/")
    return resolved


def scan_strings(
    command: list[str],
    terms: list[str],
    output_path: Path,
    encoding: str,
    records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    started_at = utc_now()
    lowered = [(term, term.lower()) for term in terms]
    hits: list[dict[str, str]] = []
    matched_lines = 0
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert process.stdout is not None
    with output_path.open("w", encoding="utf-8") as handle:
        for line in process.stdout:
            stripped = line.rstrip("\n")
            line_lower = stripped.lower()
            line_terms = [term for term, lower in lowered if lower in line_lower]
            if not line_terms:
                continue
            matched_lines += 1
            handle.write(stripped + "\n")
            if len(hits) < 120:
                hits.append({"encoding": encoding, "line": stripped, "terms": ", ".join(line_terms)})
    stderr = process.stderr.read() if process.stderr else ""
    returncode = process.wait()
    records.append(
        {
            "argv": command,
            "started_at": started_at,
            "finished_at": utc_now(),
            "returncode": returncode,
            "matched_lines": matched_lines,
            "stderr_preview": stderr[-4000:],
        }
    )
    if returncode != 0:
        raise RuntimeError(f"guest strings scan failed: {' '.join(command)}")
    return hits


def summarize_hits(
    terms: list[str],
    ascii_hits: list[dict[str, str]],
    utf16_hits: list[dict[str, str]],
) -> dict[str, Any]:
    counts = Counter()
    samples: dict[str, list[dict[str, str]]] = defaultdict(list)
    for hit in [*ascii_hits, *utf16_hits]:
        for term in [item.strip() for item in hit["terms"].split(",")]:
            counts[term] += 1
            if len(samples[term]) < 5:
                samples[term].append({"encoding": hit["encoding"], "line": hit["line"]})
    return {
        "search_terms": terms,
        "hit_counts": [{"term": term, "count": counts.get(term, 0)} for term in terms],
        "total_sampled_hits": len(ascii_hits) + len(utf16_hits),
        "hit_samples": dict(samples),
    }


def observations(summary: dict[str, Any]) -> list[str]:
    observed = [entry["term"] for entry in summary["memory"]["hit_counts"] if entry["count"]]
    return [
        "Memory string triage scanned ASCII and UTF-16LE strings with explicit search terms.",
        f"{len(observed)} of {len(summary['memory']['search_terms'])} search terms produced sampled hits.",
        "String hits are volatile pivots. Use memory-forensics tooling before promoting process conclusions.",
    ]


def hash_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size_bytes}


def zip_outputs(source_dir: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.iterdir()):
            archive.write(path, arcname=path.name)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
