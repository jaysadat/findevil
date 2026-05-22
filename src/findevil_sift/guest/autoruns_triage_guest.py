from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PATH_RISK = re.compile(r"\\(users|appdata|temp|programdata)\\", re.IGNORECASE)
SCRIPT_RISK = re.compile(r"\b(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)\b", re.IGNORECASE)
SCRIPT_PAYLOAD_RISK = re.compile(
    r"(frombase64string|encodedcommand|\biex\s*\(|-nop\b|-w\s+hidden\b|getvalue\s*\()",
    re.IGNORECASE,
)
PERSISTENCE_CATEGORIES = {"services", "drivers"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    zip_path = validate_zip_path(Path(args.zip))
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    decoded_dir = output_dir / "autoruns"
    decoded_dir.mkdir(exist_ok=True)

    before = hash_file(zip_path)
    member, rows, decoded_text = read_autoruns_csv(zip_path)
    after = hash_file(zip_path)
    decoded_csv = decoded_dir / "autoruns-decoded.csv"
    decoded_csv.write_text(decoded_text, encoding="utf-8")

    summary = {
        "generated_at": utc_now(),
        "evidence": {
            "path": str(zip_path),
            "before_sha256": before["sha256"],
            "after_sha256": after["sha256"],
            "size_bytes": before["size_bytes"],
            "unchanged": before == after,
        },
        "autoruns": summarize_rows(member, rows),
        "commands": [
            {
                "operation": "python_zipfile_csv_decode",
                "inputs": [str(zip_path), member],
                "outputs": [str(decoded_csv)],
            }
        ],
    }
    summary["observations"] = observations(summary)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    zip_outputs(decoded_dir, output_dir / "autoruns-outputs.zip")
    return 0


def validate_zip_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.suffix.lower() != ".zip":
        raise ValueError("Autoruns evidence must be a ZIP file")
    if not str(resolved).startswith("/cases/"):
        raise ValueError("Autoruns evidence must live below /cases/")
    return resolved


def read_autoruns_csv(zip_path: Path) -> tuple[str, list[dict[str, str]], str]:
    with zipfile.ZipFile(zip_path) as archive:
        members = [name for name in archive.namelist() if name.lower().endswith(".csv")]
        if len(members) != 1:
            raise ValueError("Autoruns ZIP must contain exactly one CSV member")
        member = members[0]
        raw = archive.read(member)
    decoded_text = raw.decode("utf-16")
    reader = csv.DictReader(io.StringIO(decoded_text))
    return member, [clean_row(row) for row in reader], decoded_text


def clean_row(row: dict[str, str | None]) -> dict[str, str]:
    return {(key or "").strip(): (value or "").strip() for key, value in row.items()}


def summarize_rows(member: str, rows: list[dict[str, str]]) -> dict[str, Any]:
    category_counts = Counter(row.get("Category") or "(blank)" for row in rows)
    signer_counts = Counter(signer_state(row.get("Signer", "")) for row in rows)
    candidates = []
    high_signal = []
    for row in rows:
        reasons = review_reasons(row)
        if reasons:
            candidate = candidate_from_row(row, reasons)
            candidates.append(candidate)
            high_signal_reasons = high_signal_reasons_for(row, reasons)
            if high_signal_reasons:
                high_signal.append(
                    {
                        **candidate,
                        "high_signal_reasons": ", ".join(high_signal_reasons),
                    }
                )

    return {
        "csv_member": member,
        "row_count": len(rows),
        "enabled_count": sum(1 for row in rows if row.get("Enabled", "").lower() == "enabled"),
        "category_counts": [
            {"category": category, "count": count}
            for category, count in category_counts.most_common(15)
        ],
        "signer_counts": [
            {"signer_state": state, "count": count}
            for state, count in signer_counts.most_common()
        ],
        "high_signal_candidates": high_signal[:15],
        "review_candidates": candidates[:30],
    }


def candidate_from_row(row: dict[str, str], reasons: list[str]) -> dict[str, str]:
    return {
        "entry": row.get("Entry", ""),
        "category": row.get("Category", ""),
        "signer": row.get("Signer", ""),
        "image_path": row.get("Image Path", ""),
        "launch_string": row.get("Launch String", ""),
        "sha256": row.get("SHA-256", ""),
        "reasons": ", ".join(reasons),
    }


def review_reasons(row: dict[str, str]) -> list[str]:
    if row.get("Enabled", "").lower() != "enabled":
        return []
    signer = row.get("Signer", "")
    image_path = row.get("Image Path", "")
    launch = row.get("Launch String", "")
    reasons = []
    if signer_state(signer) != "verified":
        reasons.append("unverified_or_missing_signer")
    if PATH_RISK.search(image_path):
        reasons.append("user_or_writable_path")
    if SCRIPT_RISK.search(launch):
        reasons.append("script_or_lolbin_launch")
    return reasons


def high_signal_reasons_for(row: dict[str, str], review_reasons: list[str]) -> list[str]:
    launch = row.get("Launch String", "")
    category = row.get("Category", "").strip().lower()
    reasons = []
    if "user_or_writable_path" in review_reasons:
        reasons.append("writable_execution_path")
    if (
        "unverified_or_missing_signer" in review_reasons
        and category in PERSISTENCE_CATEGORIES
        and row.get("SHA-256", "")
    ):
        reasons.append("unsigned_persistence_binary")
    if SCRIPT_PAYLOAD_RISK.search(launch):
        reasons.append("payload_like_script_launch")
    return reasons


def signer_state(signer: str) -> str:
    value = signer.strip().lower()
    if value.startswith("(verified)"):
        return "verified"
    if not value:
        return "missing"
    return "other"


def hash_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size_bytes}


def observations(summary: dict[str, Any]) -> list[str]:
    autoruns = summary["autoruns"]
    missing = next(
        (entry["count"] for entry in autoruns["signer_counts"] if entry["signer_state"] == "missing"),
        0,
    )
    return [
        f"Parsed {autoruns['row_count']} Autoruns rows from the exported CSV member.",
        f"{len(autoruns['high_signal_candidates'])} enabled rows met high-signal persistence heuristics.",
        f"{len(autoruns['review_candidates'])} enabled rows met review heuristics.",
        f"{missing} rows have a missing signer field; review candidates remain pivots, not confirmed persistence.",
    ]


def zip_outputs(source_dir: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.iterdir()):
            archive.write(path, arcname=path.name)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
