from __future__ import annotations

import hmac
import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Any

from .audit import hash_file

MANIFEST_NAME = "run-manifest.json"
MANIFEST_SCHEMA = "findevil.run_manifest.v1"
SIGNING_KEY_ENV = "FINDEVIL_RUN_MANIFEST_KEY"
SIGNING_KEY_ID_ENV = "FINDEVIL_RUN_MANIFEST_KEY_ID"


def write_run_manifest(
    output_root: Path,
    *,
    workflow: str,
    case_id: str,
    case_name: str,
    workflow_status: str,
    generated_at: str,
    signing_key: bytes | None = None,
    signing_key_id: str | None = None,
) -> dict[str, str | int | bool]:
    root = output_root.resolve(strict=True)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "generated_at": generated_at,
        "bundle_root": ".",
        "workflow": workflow,
        "case_id": case_id,
        "case_name": case_name,
        "workflow_status": workflow_status,
        "files": manifest_files(root),
    }
    manifest["file_count"] = len(manifest["files"])
    if signing_key:
        manifest["signature"] = sign_manifest(manifest, signing_key, signing_key_id)
    manifest_path = root / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "manifest": str(manifest_path),
        "file_count": manifest["file_count"],
        "signed": "signature" in manifest,
    }


def verify_run_manifest(
    manifest_path: Path,
    *,
    signing_key: bytes | None = None,
) -> dict[str, Any]:
    path = manifest_path.resolve(strict=True)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    validation_errors = validate_manifest_shape(manifest)
    file_results = []
    if not validation_errors:
        file_results = [verify_manifest_file(path.parent, entry) for entry in manifest["files"]]

    signature = manifest.get("signature")
    signature_result = verify_signature(manifest, signing_key) if signature else {
        "status": "not_present",
        "passed": True,
    }
    files_passed = bool(file_results) and all(result["passed"] for result in file_results)
    passed = not validation_errors and files_passed and signature_result["passed"]
    return {
        "passed": passed,
        "manifest": str(path),
        "schema": manifest.get("schema"),
        "file_count": len(file_results),
        "files_passed": files_passed,
        "signature": signature_result,
        "validation_errors": validation_errors,
        "files": file_results,
    }


def signing_key_from_environment() -> bytes | None:
    value = os.environ.get(SIGNING_KEY_ENV)
    return value.encode("utf-8") if value else None


def signing_key_id_from_environment() -> str | None:
    value = os.environ.get(SIGNING_KEY_ID_ENV)
    return value if value else None


def manifest_files(output_root: Path) -> list[dict[str, str | int]]:
    files = []
    for path in sorted(source for source in output_root.rglob("*") if source.is_file()):
        if path.name == MANIFEST_NAME and path.parent == output_root:
            continue
        digest = hash_file(path)
        files.append(
            {
                "path": path.relative_to(output_root).as_posix(),
                "algorithm": digest.algorithm,
                "digest": digest.digest,
                "size_bytes": digest.size_bytes,
            }
        )
    return files


def sign_manifest(
    manifest: dict[str, Any],
    signing_key: bytes,
    signing_key_id: str | None = None,
) -> dict[str, str]:
    signature = {
        "algorithm": "hmac-sha256",
        "digest": hmac.new(signing_key, canonical_payload(manifest), sha256).hexdigest(),
    }
    if signing_key_id:
        signature["key_id"] = signing_key_id
    return signature


def verify_signature(manifest: dict[str, Any], signing_key: bytes | None) -> dict[str, Any]:
    signature = manifest.get("signature", {})
    if not isinstance(signature, dict):
        return {"status": "malformed", "passed": False}
    if signature.get("algorithm") != "hmac-sha256":
        return {
            "status": "unsupported",
            "passed": False,
            "algorithm": signature.get("algorithm"),
        }
    if not signing_key:
        return {
            "status": "key_required",
            "passed": False,
            "algorithm": signature["algorithm"],
            "key_id": signature.get("key_id"),
        }
    unsigned_manifest = {key: value for key, value in manifest.items() if key != "signature"}
    expected = sign_manifest(unsigned_manifest, signing_key, signature.get("key_id"))["digest"]
    passed = hmac.compare_digest(signature.get("digest", ""), expected)
    return {
        "status": "verified" if passed else "mismatch",
        "passed": passed,
        "algorithm": signature["algorithm"],
        "key_id": signature.get("key_id"),
    }


def canonical_payload(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_manifest_file(bundle_root: Path, entry: dict[str, Any]) -> dict[str, Any]:
    relative = Path(entry["path"])
    if relative.is_absolute() or ".." in relative.parts:
        return {"path": entry["path"], "passed": False, "status": "unsafe_path"}
    path = (bundle_root / relative).resolve()
    if bundle_root.resolve() not in (path, *path.parents):
        return {"path": entry["path"], "passed": False, "status": "unsafe_path"}
    if not path.is_file():
        return {"path": entry["path"], "passed": False, "status": "missing"}
    digest = hash_file(path)
    passed = (
        entry.get("algorithm") == digest.algorithm
        and entry.get("digest") == digest.digest
        and entry.get("size_bytes") == digest.size_bytes
    )
    return {
        "path": entry["path"],
        "passed": passed,
        "status": "verified" if passed else "digest_mismatch",
        "algorithm": digest.algorithm,
        "digest": digest.digest,
        "size_bytes": digest.size_bytes,
    }


def validate_manifest_shape(manifest: Any) -> list[str]:
    if not isinstance(manifest, dict):
        return ["run manifest must be a JSON object"]
    errors = []
    if manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append(f"unsupported run manifest schema: {manifest.get('schema')}")
    if not isinstance(manifest.get("files"), list):
        errors.append("run manifest files must be a list")
        return errors
    if manifest.get("file_count") != len(manifest["files"]):
        errors.append("run manifest file_count does not match files")
    required_file_fields = {"path", "algorithm", "digest", "size_bytes"}
    for index, entry in enumerate(manifest["files"], start=1):
        if not isinstance(entry, dict) or not required_file_fields <= set(entry):
            errors.append(f"run manifest file {index} is missing required digest fields")
            continue
        if (
            not isinstance(entry["path"], str)
            or not isinstance(entry["algorithm"], str)
            or not isinstance(entry["digest"], str)
            or not isinstance(entry["size_bytes"], int)
        ):
            errors.append(f"run manifest file {index} has invalid digest field types")
    return errors
