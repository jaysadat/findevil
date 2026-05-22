from __future__ import annotations

import argparse
import base64
import hashlib
import gzip
import json
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RUN_ENTRY = re.compile(r"^\s{2}(.+?) - (.+)$")
FIELD = re.compile(r"^\s{2}(Name|Display|ImagePath|Type|Start|Group)\s+=\s*(.*)$")
SCRIPT_PAYLOAD_RISK = re.compile(
    r"(frombase64string|encodedcommand|\biex\s*\(|-nop\b|-w\s+hidden\b|getvalue\s*\()",
    re.IGNORECASE,
)
REGISTRY_PAYLOAD_REF = re.compile(
    r"HKLM:Software\\([^']+)'\)\.GetValue\('([^']+)'\)",
    re.IGNORECASE,
)
NESTED_GZIP_B64 = re.compile(r"FromBase64String\(''([^']+)''\)", re.IGNORECASE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    zip_path = validate_zip_path(Path(args.zip))
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    hive_dir = output_dir / "registry"
    hive_dir.mkdir(exist_ok=True)

    before = hash_file(zip_path)
    members = extract_hives(zip_path, hive_dir)
    run_output = run_regripper(hive_dir / "software", "run", hive_dir / "software-run.txt")
    services_output = run_regripper(hive_dir / "system", "services", hive_dir / "system-services.txt")
    after = hash_file(zip_path)

    summary = {
        "generated_at": utc_now(),
        "evidence": {
            "path": str(zip_path),
            "before_sha256": before["sha256"],
            "after_sha256": after["sha256"],
            "size_bytes": before["size_bytes"],
            "unchanged": before == after,
        },
        "registry": summarize_outputs(
            members,
            run_output,
            services_output,
            hive_dir / "software",
            hive_dir,
        ),
        "commands": [
            {
                "operation": "python_zipfile_extract",
                "inputs": [str(zip_path), *members],
                "outputs": [str(hive_dir / "software"), str(hive_dir / "system")],
            },
            {
                "operation": "rip.pl",
                "inputs": [str(hive_dir / "software"), "run"],
                "outputs": [str(hive_dir / "software-run.txt")],
            },
            {
                "operation": "rip.pl",
                "inputs": [str(hive_dir / "system"), "services"],
                "outputs": [str(hive_dir / "system-services.txt")],
            },
        ],
    }
    summary["observations"] = observations(summary)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    zip_outputs(hive_dir, output_dir / "registry-outputs.zip")
    return 0


def validate_zip_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.suffix.lower() != ".zip":
        raise ValueError("Protected-files evidence must be a ZIP file")
    if not str(resolved).startswith("/cases/"):
        raise ValueError("Protected-files evidence must live below /cases/")
    return resolved


def extract_hives(zip_path: Path, hive_dir: Path) -> list[str]:
    requested = {"Protected/software": "software", "Protected/system": "system"}
    with zipfile.ZipFile(zip_path) as archive:
        available = set(archive.namelist())
        missing = sorted(set(requested) - available)
        if missing:
            raise ValueError(f"Protected-files ZIP is missing required hive members: {missing}")
        for member, name in requested.items():
            (hive_dir / name).write_bytes(archive.read(member))
    return list(requested)


def run_regripper(hive_path: Path, plugin: str, destination: Path) -> str:
    completed = subprocess.run(
        ["rip.pl", "-r", str(hive_path), "-p", plugin],
        check=False,
        capture_output=True,
        text=True,
    )
    output = completed.stdout + completed.stderr
    destination.write_text(output, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"RegRipper plugin failed: {plugin}")
    return output


def summarize_outputs(
    members: list[str],
    run_output: str,
    services_output: str,
    software_hive: Path,
    output_dir: Path,
) -> dict[str, Any]:
    run_entries = parse_run_entries(run_output)
    service_entries = parse_services(services_output)
    payload_chains = decode_payload_chains(software_hive, run_entries, output_dir)
    high_signal = []
    for entry in run_entries:
        if SCRIPT_PAYLOAD_RISK.search(entry["command"]):
            high_signal.append(
                {
                    "entry": entry["name"],
                    "kind": "run_value",
                    "value": entry["command"],
                    "high_signal_reasons": "payload_like_run_command",
                }
            )
    for entry in service_entries:
        name = entry.get("name", "")
        image_path = entry.get("image_path", "")
        if "updater" in name.lower() and image_path.lower().endswith("\\coreupdater.exe"):
            high_signal.append(
                {
                    "entry": name,
                    "kind": "service",
                    "value": image_path,
                    "high_signal_reasons": "updater_autostart_service_pivot",
                }
            )
    return {
        "hive_members": members,
        "run_entry_count": len(run_entries),
        "service_entry_count": len(service_entries),
        "run_entries": run_entries[:30],
        "service_entries": service_entries[:30],
        "decoded_payload_chains": payload_chains,
        "high_signal_candidates": high_signal[:15],
    }


def parse_run_entries(output: str) -> list[dict[str, str]]:
    entries = []
    for line in output.splitlines():
        match = RUN_ENTRY.match(line)
        if match:
            entries.append({"name": match.group(1), "command": match.group(2)})
    return entries


def parse_services(output: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        match = FIELD.match(line)
        if not match:
            continue
        key = match.group(1).lower().replace("imagepath", "image_path")
        if key == "name" and current:
            entries.append(current)
            current = {}
        current[key] = match.group(2)
    if current:
        entries.append(current)
    return entries


def decode_payload_chains(
    software_hive: Path,
    run_entries: list[dict[str, str]],
    output_dir: Path,
) -> list[dict[str, Any]]:
    chains = []
    seen = set()
    for entry in run_entries:
        for key_path, value_name in REGISTRY_PAYLOAD_REF.findall(entry["command"]):
            reference = (key_path, value_name)
            if reference in seen:
                continue
            seen.add(reference)
            value = query_software_value(software_hive, key_path, value_name)
            chain = decode_registry_payload(value, output_dir)
            chain["run_entry"] = entry["name"]
            chains.append(chain)
    return chains


def query_software_value(software_hive: Path, key_path: str, value_name: str) -> dict[str, Any]:
    perl = (
        "$r=Parse::Win32Registry->new($ARGV[0]);"
        "$k=$r->get_root_key->get_subkey($ARGV[1]);die \"key missing\\n\" unless $k;"
        "$v=$k->get_value($ARGV[2]);die \"value missing\\n\" unless $v;"
        "print encode_json({key_path=>$ARGV[1],key_last_write=>$k->get_timestamp(),"
        "value_name=>$v->get_name(),value_type=>$v->get_type_as_string(),data=>$v->get_data()});"
    )
    completed = subprocess.run(
        ["perl", "-MParse::Win32Registry", "-MJSON::PP", "-e", perl, str(software_hive), key_path, value_name],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"SOFTWARE payload value query failed: {completed.stderr.strip()}")
    return json.loads(completed.stdout)


def decode_registry_payload(value: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    label = safe_label(f"{value['key_path']}-{value['value_name']}")
    encoded = value["data"]
    outer = base64.b64decode(encoded).decode("utf-16le", errors="replace")
    outer_path = output_dir / f"{label}-outer.ps1.txt"
    outer_path.write_text(outer, encoding="utf-8")
    nested_match = NESTED_GZIP_B64.search(outer)
    nested = ""
    nested_path: Path | None = None
    if nested_match:
        nested = gzip.decompress(base64.b64decode(nested_match.group(1))).decode(
            "utf-8",
            errors="replace",
        )
        nested_path = output_dir / f"{label}-nested.ps1.txt"
        nested_path.write_text(nested, encoding="utf-8")
    return {
        "key_path": value["key_path"],
        "key_last_write_epoch": value["key_last_write"],
        "value_name": value["value_name"],
        "value_type": value["value_type"],
        "encoded_chars": len(encoded),
        "outer_script": script_metadata(outer, outer_path),
        "nested_script": script_metadata(nested, nested_path) if nested_path else None,
    }


def script_metadata(text: str, path: Path | None) -> dict[str, Any]:
    return {
        "path": str(path) if path else None,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "chars": len(text),
        "indicators": [
            indicator
            for indicator in (
                "GzipStream",
                "VirtualAlloc",
                "CreateThread",
                "WaitForSingleObject",
                "FromBase64String",
            )
            if indicator.lower() in text.lower()
        ],
    }


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._").lower() or "payload"


def observations(summary: dict[str, Any]) -> list[str]:
    registry = summary["registry"]
    emitted = [
        "RegRipper parsed the exported SOFTWARE Run keys and SYSTEM services hive surface.",
        f"{registry['run_entry_count']} Run entries and {registry['service_entry_count']} service entries were parsed.",
        f"{len(registry['high_signal_candidates'])} registry persistence pivots met high-signal heuristics.",
    ]
    if registry["decoded_payload_chains"]:
        emitted.append(
            f"{len(registry['decoded_payload_chains'])} referenced SOFTWARE payload value was decoded "
            "to preserved PowerShell text without execution."
        )
    return emitted


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
            if path.suffix == ".txt":
                archive.write(path, arcname=path.name)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
