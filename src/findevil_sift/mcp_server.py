from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .correlate import correlate_case_summaries, write_case_correlation
from .vmware import (
    SiftVmConfig,
    triage_guest_autoruns,
    triage_guest_disk,
    triage_guest_pcap,
    triage_guest_memory,
    triage_guest_registry,
    triage_guest_userassist,
    inventory_guest_case,
)

mcp = FastMCP(
    "Find Evil SIFT",
    instructions=(
        "Use these tools for constrained DFIR operations against the SIFT guest. "
        "Do not claim a finding is confirmed unless the returned evidence and preserved "
        "tool outputs support it."
    ),
    json_response=True,
)


@mcp.tool()
def sift_pcap_triage(guest_pcap_path: str, case_label: str = "pcap") -> dict[str, Any]:
    """Run evidence-safe Zeek triage for one PCAP that already lives below /cases."""
    output_dir = next_output_dir(case_label)
    return triage_guest_pcap(
        config=SiftVmConfig.from_environment(),
        guest_pcap_path=guest_pcap_path,
        output_dir=output_dir,
    )


@mcp.tool()
def sift_pcap_policy() -> dict[str, Any]:
    """Describe the current PCAP triage trust boundary and outputs."""
    return {
        "guest_evidence_scope": "/cases/**/*.pcap or /cases/**/*.pcapng",
        "guest_commands": ["capinfos", "zeek readpcap"],
        "host_outputs": ["summary.json", "report.md", "zeek-logs.zip", "guest-run.log"],
        "integrity": "SHA-256 is recorded before and after guest analysis.",
        "output_root": str(output_root()),
    }


@mcp.tool()
def sift_disk_triage(guest_e01_path: str, case_label: str = "disk") -> dict[str, Any]:
    """Run mount-free Sleuth Kit triage for one E01 primary segment below /cases."""
    output_dir = next_output_dir(case_label)
    return triage_guest_disk(
        config=SiftVmConfig.from_environment(),
        guest_e01_path=guest_e01_path,
        output_dir=output_dir,
    )


@mcp.tool()
def sift_disk_policy() -> dict[str, Any]:
    """Describe the current disk-image triage trust boundary and outputs."""
    return {
        "guest_evidence_scope": "/cases/**/*.E01",
        "guest_commands": ["ewfinfo", "mmls", "fsstat", "fls"],
        "mounts": "none in the current disk lane",
        "host_outputs": ["summary.json", "report.md", "tsk-outputs.zip", "guest-run.log"],
        "integrity": "SHA-256 is recorded for EWF segments before and after triage.",
        "output_root": str(output_root()),
    }


@mcp.tool()
def sift_autoruns_triage(guest_zip_path: str, case_label: str = "autoruns") -> dict[str, Any]:
    """Triage one exported Autoruns ZIP below /cases and preserve decoded CSV output."""
    return triage_guest_autoruns(
        config=SiftVmConfig.from_environment(),
        guest_zip_path=guest_zip_path,
        output_dir=next_output_dir(case_label),
    )


@mcp.tool()
def sift_autoruns_policy() -> dict[str, Any]:
    """Describe the exported Autoruns ZIP triage boundary and outputs."""
    return {
        "guest_evidence_scope": "/cases/**/*.zip with exactly one Autoruns CSV member",
        "guest_operations": ["python zipfile CSV decode"],
        "host_outputs": ["summary.json", "report.md", "autoruns-outputs.zip", "guest-run.log"],
        "integrity": "SHA-256 is recorded for the ZIP before and after triage.",
        "output_root": str(output_root()),
    }


@mcp.tool()
def sift_registry_triage(guest_zip_path: str, case_label: str = "registry") -> dict[str, Any]:
    """Triage exported protected SOFTWARE and SYSTEM hives from one ZIP below /cases."""
    return triage_guest_registry(
        config=SiftVmConfig.from_environment(),
        guest_zip_path=guest_zip_path,
        output_dir=next_output_dir(case_label),
    )


@mcp.tool()
def sift_registry_policy() -> dict[str, Any]:
    """Describe the protected registry ZIP triage boundary and outputs."""
    return {
        "guest_evidence_scope": "/cases/**/*.zip with Protected/software and Protected/system",
        "guest_commands": ["rip.pl -p run", "rip.pl -p services"],
        "host_outputs": ["summary.json", "report.md", "registry-outputs.zip", "guest-run.log"],
        "integrity": "SHA-256 is recorded for the ZIP before and after triage.",
        "output_root": str(output_root()),
    }


@mcp.tool()
def sift_userassist_triage(guest_zip_path: str, case_label: str = "userassist") -> dict[str, Any]:
    """Triage exported NTUSER hives in one ZIP below /cases with UserAssist."""
    return triage_guest_userassist(
        config=SiftVmConfig.from_environment(),
        guest_zip_path=guest_zip_path,
        output_dir=next_output_dir(case_label),
    )


@mcp.tool()
def sift_userassist_policy() -> dict[str, Any]:
    """Describe the exported UserAssist ZIP triage boundary and outputs."""
    return {
        "guest_evidence_scope": "/cases/**/*.zip with Users/<profile>/NTUSER.DAT",
        "guest_commands": ["rip.pl -p userassist"],
        "host_outputs": ["summary.json", "report.md", "userassist-outputs.zip", "guest-run.log"],
        "integrity": "SHA-256 is recorded for the ZIP before and after triage.",
        "limits": "UserAssist is execution context and must be correlated before promotion.",
        "output_root": str(output_root()),
    }


@mcp.tool()
def sift_memory_triage(
    guest_memory_path: str,
    terms: list[str],
    case_label: str = "memory",
) -> dict[str, Any]:
    """Run bounded memory string-hit triage for explicit search terms below /cases."""
    return triage_guest_memory(
        config=SiftVmConfig.from_environment(),
        guest_memory_path=guest_memory_path,
        terms=terms,
        output_dir=next_output_dir(case_label),
    )


@mcp.tool()
def sift_memory_policy() -> dict[str, Any]:
    """Describe bounded memory string-hit triage and its limits."""
    return {
        "guest_evidence_scope": "/cases/**/*.mem, /cases/**/*.raw, or /cases/**/*.bin",
        "guest_commands": ["strings -a -n 6", "strings -a -el -n 6"],
        "host_outputs": ["summary.json", "report.md", "memory-string-hits.zip", "guest-run.log"],
        "integrity": "SHA-256 is recorded for the memory file before and after triage.",
        "limits": "String hits are pivots; use memory-forensics plugins before process conclusions.",
        "output_root": str(output_root()),
    }


@mcp.tool()
def sift_case_inventory(guest_case_root: str, case_label: str = "inventory") -> dict[str, Any]:
    """Inventory candidate lane artifacts below one SIFT /cases case root."""
    return inventory_guest_case(
        config=SiftVmConfig.from_environment(),
        guest_case_root=guest_case_root,
        output_dir=next_output_dir(case_label),
    )


@mcp.tool()
def sift_case_inventory_policy() -> dict[str, Any]:
    """Describe the bounded case-root inventory trust boundary and outputs."""
    return {
        "guest_evidence_scope": "one existing directory below /cases/",
        "guest_operations": [
            "bounded pathlib file inventory",
            "bounded ZIP member-name inspection for Autoruns and protected registry candidates",
        ],
        "host_outputs": ["inventory.json", "report.md", "guest-run.log"],
        "limits": "Discovery candidates are heuristic and require analyst review before triage.",
        "output_root": str(output_root()),
    }


@mcp.tool()
def sift_case_correlation(
    pcap_summary_path: str,
    disk_summary_path: str,
    autoruns_summary_path: str | None = None,
    registry_summary_path: str | None = None,
    userassist_summary_path: str | None = None,
    memory_summary_path: str | None = None,
    case_label: str = "correlation",
) -> dict[str, Any]:
    """Correlate preserved local lane summaries into a case pivot report."""
    correlation = correlate_case_summaries(
        Path(pcap_summary_path),
        Path(disk_summary_path),
        Path(autoruns_summary_path) if autoruns_summary_path else None,
        Path(registry_summary_path) if registry_summary_path else None,
        Path(userassist_summary_path) if userassist_summary_path else None,
        Path(memory_summary_path) if memory_summary_path else None,
    )
    outputs = write_case_correlation(correlation, next_output_dir(case_label))
    return {"status": "ok", **outputs}


def output_root() -> Path:
    return Path(os.environ.get("FINDEVIL_OUTPUT_ROOT", "artifacts/mcp"))


def next_output_dir(case_label: str) -> Path:
    safe_label = re.sub(r"[^A-Za-z0-9._-]+", "-", case_label).strip("-._") or "pcap"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return output_root() / f"{timestamp}-{safe_label}"


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
