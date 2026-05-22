from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class EvidenceDigest:
    path: str
    algorithm: str
    digest: str
    size_bytes: int


@dataclass(frozen=True)
class AuditRecord:
    tool_name: str
    status: str
    started_at: str
    finished_at: str
    inputs: dict[str, Any]
    outputs: dict[str, Any]
    evidence_before: list[EvidenceDigest] = field(default_factory=list)
    evidence_after: list[EvidenceDigest] = field(default_factory=list)
    record_id: str = field(default_factory=lambda: str(uuid4()))

    @classmethod
    def create(
        cls,
        *,
        tool_name: str,
        status: str,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
        evidence_before: list[EvidenceDigest] | None = None,
        evidence_after: list[EvidenceDigest] | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> "AuditRecord":
        start = _utc_timestamp(started_at)
        finish = _utc_timestamp(finished_at)
        return cls(
            tool_name=tool_name,
            status=status,
            started_at=start,
            finished_at=finish,
            inputs=inputs,
            outputs=outputs,
            evidence_before=evidence_before or [],
            evidence_after=evidence_after or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def hash_file(path: str | Path) -> EvidenceDigest:
    source = Path(path)
    digest = sha256()
    size_bytes = 0

    with source.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)

    return EvidenceDigest(
        path=str(source),
        algorithm="sha256",
        digest=digest.hexdigest(),
        size_bytes=size_bytes,
    )


def _utc_timestamp(value: datetime | None) -> str:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

