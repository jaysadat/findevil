from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_ENV = "FINDEVIL_SIFT_CONFIG"
HOST_CONFIG_FIELDS = {"vmx_path", "guest_user", "vmrun_path"}
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

    unexpected_sections = sorted(set(config) - {"sift_vm"})
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
    return {"path": str(path), "sift_vm": sift_vm}
