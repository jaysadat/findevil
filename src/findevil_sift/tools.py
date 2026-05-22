from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditRecord, hash_file


def hash_evidence(path: str | Path) -> AuditRecord:
    started_at = datetime.now(timezone.utc)
    evidence_before = hash_file(path)
    evidence_after = hash_file(path)
    finished_at = datetime.now(timezone.utc)

    status = "ok"
    if evidence_before.digest != evidence_after.digest:
        status = "evidence_changed"

    return AuditRecord.create(
        tool_name="hash_evidence",
        status=status,
        inputs={"path": str(path)},
        outputs={
            "algorithm": evidence_before.algorithm,
            "digest": evidence_before.digest,
            "size_bytes": evidence_before.size_bytes,
        },
        evidence_before=[evidence_before],
        evidence_after=[evidence_after],
        started_at=started_at,
        finished_at=finished_at,
    )

