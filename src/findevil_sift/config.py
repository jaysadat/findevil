from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_ENV = "FINDEVIL_SIFT_CONFIG"
HOST_CONFIG_FIELDS = {"vmx_path", "guest_user", "vmrun_path"}
OPERATOR_POLICY_FIELDS = {
    "allowed_output_roots",
    "approved_knowledge_index_roots",
    "require_signed_run_manifests",
}
SECRET_FIELDS = {"password", "guest_password", "guest_token", "token"}


def load_host_config(config_path: str | Path | None = None) -> dict[str, Any]:
    selected = config_path or os.environ.get(CONFIG_ENV)
    if not selected:
        return {}

    path = Path(selected).expanduser().resolve(strict=True)
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"host config is not valid JSON: {path}: {exc.msg}") from exc
    if not isinstance(config, dict):
        raise ValueError(f"host config must be a JSON object: {path}")

    unexpected_sections = sorted(set(config) - {"sift_vm", "operator_policy"})
    if unexpected_sections:
        raise ValueError(f"host config has unsupported sections: {', '.join(unexpected_sections)}")
    sift_vm = config.get("sift_vm", {})
    if not isinstance(sift_vm, dict):
        raise ValueError("host config sift_vm section must be an object")
    secret_fields = sorted(set(sift_vm) & SECRET_FIELDS)
    if secret_fields:
        raise ValueError(
            "host config must not store SIFT guest secrets: "
            f"{', '.join(secret_fields)}; use SIFT_GUEST_PASSWORD instead"
        )
    unexpected_fields = sorted(set(sift_vm) - HOST_CONFIG_FIELDS)
    if unexpected_fields:
        raise ValueError(f"host config sift_vm has unsupported fields: {', '.join(unexpected_fields)}")
    invalid_fields = sorted(
        field
        for field, value in sift_vm.items()
        if not isinstance(value, str) or not value.strip()
    )
    if invalid_fields:
        raise ValueError(f"host config sift_vm fields must be non-empty strings: {', '.join(invalid_fields)}")
    operator_policy = validate_operator_policy(config.get("operator_policy", {}), path)
    return {"path": str(path), "sift_vm": sift_vm, "operator_policy": operator_policy}


def load_operator_policy(config_path: str | Path | None = None) -> dict[str, Any]:
    config = load_host_config(config_path)
    return config.get(
        "operator_policy",
        {
            "allowed_output_roots": [],
            "approved_knowledge_index_roots": [],
            "require_signed_run_manifests": False,
        },
    )


def enforce_workflow_policy(
    output_root: Path,
    *,
    signing_key_present: bool,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    policy = load_operator_policy(config_path)
    resolved_output = output_root.expanduser().resolve()
    allowed_roots = [Path(root) for root in policy["allowed_output_roots"]]
    if allowed_roots and not any(resolved_output.is_relative_to(root) for root in allowed_roots):
        allowed = ", ".join(str(root) for root in allowed_roots)
        raise ValueError(f"workflow output root is outside operator policy allowed_output_roots: {allowed}")
    if policy["require_signed_run_manifests"] and not signing_key_present:
        raise ValueError(
            "operator policy requires signed run manifests; set FINDEVIL_RUN_MANIFEST_KEY"
        )
    return policy


def enforce_knowledge_index_policy(
    index_path: Path,
    *,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    policy = load_operator_policy(config_path)
    resolved_index = index_path.expanduser().resolve()
    approved_roots = [Path(root) for root in policy["approved_knowledge_index_roots"]]
    if approved_roots and not any(resolved_index.is_relative_to(root) for root in approved_roots):
        approved = ", ".join(str(root) for root in approved_roots)
        raise ValueError(
            "knowledge index is outside operator policy approved_knowledge_index_roots: "
            f"{approved}"
        )
    return policy


def validate_operator_policy(policy: Any, config_path: Path) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise ValueError("host config operator_policy section must be an object")
    unexpected_fields = sorted(set(policy) - OPERATOR_POLICY_FIELDS)
    if unexpected_fields:
        raise ValueError(
            f"host config operator_policy has unsupported fields: {', '.join(unexpected_fields)}"
        )
    allowed_output_roots = policy.get("allowed_output_roots", [])
    if not isinstance(allowed_output_roots, list) or any(
        not isinstance(root, str) or not root.strip() for root in allowed_output_roots
    ):
        raise ValueError("host config operator_policy allowed_output_roots must be non-empty path strings")
    approved_knowledge_index_roots = policy.get("approved_knowledge_index_roots", [])
    if not isinstance(approved_knowledge_index_roots, list) or any(
        not isinstance(root, str) or not root.strip() for root in approved_knowledge_index_roots
    ):
        raise ValueError(
            "host config operator_policy approved_knowledge_index_roots "
            "must be non-empty path strings"
        )
    require_signed = policy.get("require_signed_run_manifests", False)
    if not isinstance(require_signed, bool):
        raise ValueError(
            "host config operator_policy require_signed_run_manifests must be a boolean"
        )
    return {
        "allowed_output_roots": [
            str(resolve_config_path(config_path, root)) for root in allowed_output_roots
        ],
        "approved_knowledge_index_roots": [
            str(resolve_config_path(config_path, root)) for root in approved_knowledge_index_roots
        ],
        "require_signed_run_manifests": require_signed,
    }


def resolve_config_path(config_path: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config_path.parent / path
    return path.resolve()
