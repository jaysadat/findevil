from __future__ import annotations

import argparse
import json
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MEMORY_SUFFIXES = {".mem", ".raw", ".bin"}
MAX_FILES = 5000
ZIP_MEMBER_SAMPLE = 250


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-root", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    case_root = validate_case_root(Path(args.case_root))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = inventory_case(case_root)
    (args.output_dir / "inventory.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return 0


def validate_case_root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"case root is not a directory: {resolved}")
    if not str(resolved).startswith("/cases/"):
        raise ValueError("case root must live below /cases/")
    return resolved


def inventory_case(case_root: Path) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    scanned_files = 0
    truncated = False
    for path in sorted(case_root.rglob("*")):
        if not path.is_file():
            continue
        scanned_files += 1
        if scanned_files > MAX_FILES:
            truncated = True
            break
        candidates.extend(classify_path(path))

    counts = Counter(candidate["lane"] for candidate in candidates)
    return {
        "generated_at": utc_now(),
        "case_root": str(case_root),
        "limits": {"max_files": MAX_FILES, "zip_member_sample": ZIP_MEMBER_SAMPLE},
        "scan": {
            "scanned_files": min(scanned_files, MAX_FILES),
            "truncated": truncated,
            "candidate_count": len(candidates),
        },
        "candidates": candidates,
        "candidate_counts": [
            {"lane": lane, "count": counts[lane]} for lane in sorted(counts)
        ],
        "observations": observations(counts, truncated),
    }


def classify_path(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".pcap", ".pcapng"}:
        return [candidate("pcap", path, "pcap_suffix")]
    if suffix == ".e01":
        return [candidate("disk", path, "ewf_primary_segment")]
    if suffix in MEMORY_SUFFIXES:
        return [candidate("memory", path, "memory_suffix")]
    if suffix == ".zip":
        return classify_zip(path)
    return []


def classify_zip(path: Path) -> list[dict[str, Any]]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()[:ZIP_MEMBER_SAMPLE]
    except (OSError, zipfile.BadZipFile):
        return []

    lowered = [name.lower() for name in names]
    candidates = []
    if "protected/software" in lowered and "protected/system" in lowered:
        candidates.append(
            candidate(
                "registry",
                path,
                "protected_software_system_members",
                {"zip_member_sample": names[:20]},
            )
        )
    if any(name.startswith("users/") and name.endswith("/ntuser.dat") for name in lowered):
        candidates.append(
            candidate(
                "userassist",
                path,
                "exported_ntuser_hive_members",
                {"zip_member_sample": names[:20]},
            )
        )
    csv_members = [name for name in lowered if name.endswith(".csv")]
    if csv_members and any("autorun" in name for name in lowered + [path.name.lower()]):
        candidates.append(
            candidate(
                "autoruns",
                path,
                "autoruns_csv_zip",
                {"zip_member_sample": names[:20]},
            )
        )
    return candidates


def candidate(lane: str, path: Path, reason: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    emitted = {
        "lane": lane,
        "guest_path": str(path),
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "reason": reason,
    }
    if extra:
        emitted.update(extra)
    return emitted


def observations(counts: Counter[str], truncated: bool) -> list[str]:
    emitted = [
        "Inventory classification is filename- and ZIP-member-based and must be reviewed before triage.",
    ]
    if counts:
        emitted.append(
            "Candidate lanes observed: "
            + ", ".join(f"{lane}={counts[lane]}" for lane in sorted(counts))
            + "."
        )
    if truncated:
        emitted.append(f"Inventory stopped after {MAX_FILES} files; narrow the case root if needed.")
    return emitted


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
