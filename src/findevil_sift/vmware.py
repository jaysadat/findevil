from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import uuid4

from .config import load_host_config
from .reports import (
    write_autoruns_report,
    write_disk_report,
    write_memory_report,
    write_pcap_report,
    write_registry_report,
    write_case_inventory_report,
    write_userassist_report,
)

DEFAULT_VMRUN_PATH = Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")
DEFAULT_VMX_PATH = Path(r"E:\Ollama\SIFT\SIFT.vmx")


@dataclass(frozen=True)
class SiftVmConfig:
    vmx_path: Path
    guest_user: str
    guest_password: str
    vmrun_path: Path = DEFAULT_VMRUN_PATH

    @classmethod
    def from_environment(
        cls,
        vmx_path: str | None = None,
        host_config_path: str | Path | None = None,
    ) -> "SiftVmConfig":
        password = os.environ.get("SIFT_GUEST_PASSWORD")
        if not password:
            raise ValueError("Set SIFT_GUEST_PASSWORD before using SIFT guest tools.")
        host_config = load_host_config(host_config_path).get("sift_vm", {})

        return cls(
            vmx_path=Path(
                vmx_path
                or os.environ.get("SIFT_VMX_PATH")
                or host_config.get("vmx_path", DEFAULT_VMX_PATH)
            ),
            guest_user=os.environ.get(
                "SIFT_GUEST_USER",
                host_config.get("guest_user", "sansforensics"),
            ),
            guest_password=password,
            vmrun_path=Path(
                os.environ.get("VMRUN_PATH")
                or host_config.get("vmrun_path", DEFAULT_VMRUN_PATH)
            ),
        )


class VmrunClient:
    def __init__(self, config: SiftVmConfig) -> None:
        self.config = config
        if not config.vmrun_path.exists():
            raise FileNotFoundError(f"vmrun not found: {config.vmrun_path}")
        if not config.vmx_path.exists():
            raise FileNotFoundError(f"SIFT VMX not found: {config.vmx_path}")

    def ensure_running(self) -> None:
        listed = self._run("list").stdout.splitlines()
        if str(self.config.vmx_path) not in listed:
            self._run("start", str(self.config.vmx_path), "nogui")

        state = self._guest("checkToolsState").stdout.strip()
        if state not in {"installed", "running"}:
            raise RuntimeError(f"VMware Tools are not ready in the SIFT guest: {state}")

    def run_guest_script(self, script: str) -> None:
        self._guest("runScriptInGuest", "/bin/bash", script)

    def copy_to_guest(self, source: Path, destination: PurePosixPath) -> None:
        self._guest("copyFileFromHostToGuest", str(source), str(destination))

    def copy_from_guest(self, source: PurePosixPath, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._guest("copyFileFromGuestToHost", str(source), str(destination))

    def _guest(self, command: str, *args: str) -> subprocess.CompletedProcess[str]:
        return self._run(
            "-gu",
            self.config.guest_user,
            "-gp",
            self.config.guest_password,
            command,
            str(self.config.vmx_path),
            *args,
        )

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [str(self.config.vmrun_path), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
            raise RuntimeError(f"vmrun failed for {' '.join(args[:2])}: {output.strip()}")
        return completed


def triage_guest_pcap(
    *,
    config: SiftVmConfig,
    guest_pcap_path: str,
    output_dir: Path,
) -> dict[str, object]:
    client = VmrunClient(config)
    client.ensure_running()
    output_dir.mkdir(parents=True, exist_ok=True)

    job_id = f"pcap-{uuid4().hex[:12]}"
    guest_job = PurePosixPath("/tmp/findevil-sift") / job_id
    guest_analyzer = guest_job / "pcap_triage_guest.py"
    guest_summary = guest_job / "summary.json"
    guest_logs_zip = guest_job / "zeek-logs.zip"
    guest_run_log = guest_job / "guest-run.log"
    local_analyzer = Path(__file__).with_name("guest") / "pcap_triage_guest.py"

    client.run_guest_script(f"set -eu\nmkdir -p {shlex.quote(str(guest_job))}\n")
    client.copy_to_guest(local_analyzer, guest_analyzer)

    command = " ".join(
        [
            "python3",
            shlex.quote(str(guest_analyzer)),
            "--pcap",
            shlex.quote(guest_pcap_path),
            "--output-dir",
            shlex.quote(str(guest_job)),
        ]
    )
    client.run_guest_script(
        "set -eu\n"
        f"{command} > {shlex.quote(str(guest_run_log))} 2>&1\n"
    )

    summary_path = output_dir / "summary.json"
    client.copy_from_guest(guest_summary, summary_path)
    client.copy_from_guest(guest_logs_zip, output_dir / "zeek-logs.zip")
    client.copy_from_guest(guest_run_log, output_dir / "guest-run.log")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    write_pcap_report(summary, output_dir / "report.md")
    return {
        "status": "ok",
        "output_dir": str(output_dir),
        "report": str(output_dir / "report.md"),
        "summary": str(summary_path),
        "zeek_logs": str(output_dir / "zeek-logs.zip"),
        "evidence_unchanged": summary["evidence"]["unchanged"],
        "zeek_log_count": len(summary["zeek_logs"]),
    }


def triage_guest_disk(
    *,
    config: SiftVmConfig,
    guest_e01_path: str,
    output_dir: Path,
) -> dict[str, object]:
    client = VmrunClient(config)
    client.ensure_running()
    output_dir.mkdir(parents=True, exist_ok=True)

    job_id = f"disk-{uuid4().hex[:12]}"
    guest_job = PurePosixPath("/tmp/findevil-sift") / job_id
    guest_analyzer = guest_job / "disk_triage_guest.py"
    guest_summary = guest_job / "summary.json"
    guest_outputs_zip = guest_job / "tsk-outputs.zip"
    guest_run_log = guest_job / "guest-run.log"
    local_analyzer = Path(__file__).with_name("guest") / "disk_triage_guest.py"

    client.run_guest_script(f"set -eu\nmkdir -p {shlex.quote(str(guest_job))}\n")
    client.copy_to_guest(local_analyzer, guest_analyzer)

    command = " ".join(
        [
            "python3",
            shlex.quote(str(guest_analyzer)),
            "--e01",
            shlex.quote(guest_e01_path),
            "--output-dir",
            shlex.quote(str(guest_job)),
        ]
    )
    client.run_guest_script(
        "set -eu\n"
        f"{command} > {shlex.quote(str(guest_run_log))} 2>&1\n"
    )

    summary_path = output_dir / "summary.json"
    client.copy_from_guest(guest_summary, summary_path)
    client.copy_from_guest(guest_outputs_zip, output_dir / "tsk-outputs.zip")
    client.copy_from_guest(guest_run_log, output_dir / "guest-run.log")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    write_disk_report(summary, output_dir / "report.md")
    return {
        "status": "ok",
        "output_dir": str(output_dir),
        "report": str(output_dir / "report.md"),
        "summary": str(summary_path),
        "tsk_outputs": str(output_dir / "tsk-outputs.zip"),
        "evidence_unchanged": summary["evidence"]["unchanged"],
        "artifact_categories": len(summary["filesystem"]["artifact_counts"]),
    }


def triage_guest_autoruns(
    *,
    config: SiftVmConfig,
    guest_zip_path: str,
    output_dir: Path,
) -> dict[str, object]:
    client = VmrunClient(config)
    client.ensure_running()
    output_dir.mkdir(parents=True, exist_ok=True)

    job_id = f"autoruns-{uuid4().hex[:12]}"
    guest_job = PurePosixPath("/tmp/findevil-sift") / job_id
    guest_analyzer = guest_job / "autoruns_triage_guest.py"
    guest_summary = guest_job / "summary.json"
    guest_outputs_zip = guest_job / "autoruns-outputs.zip"
    guest_run_log = guest_job / "guest-run.log"
    local_analyzer = Path(__file__).with_name("guest") / "autoruns_triage_guest.py"

    client.run_guest_script(f"set -eu\nmkdir -p {shlex.quote(str(guest_job))}\n")
    client.copy_to_guest(local_analyzer, guest_analyzer)

    command = " ".join(
        [
            "python3",
            shlex.quote(str(guest_analyzer)),
            "--zip",
            shlex.quote(guest_zip_path),
            "--output-dir",
            shlex.quote(str(guest_job)),
        ]
    )
    client.run_guest_script(
        "set -eu\n"
        f"{command} > {shlex.quote(str(guest_run_log))} 2>&1\n"
    )

    summary_path = output_dir / "summary.json"
    client.copy_from_guest(guest_summary, summary_path)
    client.copy_from_guest(guest_outputs_zip, output_dir / "autoruns-outputs.zip")
    client.copy_from_guest(guest_run_log, output_dir / "guest-run.log")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    write_autoruns_report(summary, output_dir / "report.md")
    return {
        "status": "ok",
        "output_dir": str(output_dir),
        "report": str(output_dir / "report.md"),
        "summary": str(summary_path),
        "autoruns_outputs": str(output_dir / "autoruns-outputs.zip"),
        "evidence_unchanged": summary["evidence"]["unchanged"],
        "high_signal_candidates": len(summary["autoruns"]["high_signal_candidates"]),
        "review_candidates": len(summary["autoruns"]["review_candidates"]),
    }


def triage_guest_registry(
    *,
    config: SiftVmConfig,
    guest_zip_path: str,
    output_dir: Path,
) -> dict[str, object]:
    client = VmrunClient(config)
    client.ensure_running()
    output_dir.mkdir(parents=True, exist_ok=True)

    job_id = f"registry-{uuid4().hex[:12]}"
    guest_job = PurePosixPath("/tmp/findevil-sift") / job_id
    guest_analyzer = guest_job / "registry_triage_guest.py"
    guest_summary = guest_job / "summary.json"
    guest_outputs_zip = guest_job / "registry-outputs.zip"
    guest_run_log = guest_job / "guest-run.log"
    local_analyzer = Path(__file__).with_name("guest") / "registry_triage_guest.py"

    client.run_guest_script(f"set -eu\nmkdir -p {shlex.quote(str(guest_job))}\n")
    client.copy_to_guest(local_analyzer, guest_analyzer)

    command = " ".join(
        [
            "python3",
            shlex.quote(str(guest_analyzer)),
            "--zip",
            shlex.quote(guest_zip_path),
            "--output-dir",
            shlex.quote(str(guest_job)),
        ]
    )
    client.run_guest_script(
        "set -eu\n"
        f"{command} > {shlex.quote(str(guest_run_log))} 2>&1\n"
    )

    summary_path = output_dir / "summary.json"
    client.copy_from_guest(guest_summary, summary_path)
    client.copy_from_guest(guest_outputs_zip, output_dir / "registry-outputs.zip")
    client.copy_from_guest(guest_run_log, output_dir / "guest-run.log")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    write_registry_report(summary, output_dir / "report.md")
    return {
        "status": "ok",
        "output_dir": str(output_dir),
        "report": str(output_dir / "report.md"),
        "summary": str(summary_path),
        "registry_outputs": str(output_dir / "registry-outputs.zip"),
        "evidence_unchanged": summary["evidence"]["unchanged"],
        "high_signal_candidates": len(summary["registry"]["high_signal_candidates"]),
    }


def triage_guest_memory(
    *,
    config: SiftVmConfig,
    guest_memory_path: str,
    terms: list[str],
    output_dir: Path,
) -> dict[str, object]:
    client = VmrunClient(config)
    client.ensure_running()
    output_dir.mkdir(parents=True, exist_ok=True)

    job_id = f"memory-{uuid4().hex[:12]}"
    guest_job = PurePosixPath("/tmp/findevil-sift") / job_id
    guest_analyzer = guest_job / "memory_triage_guest.py"
    guest_summary = guest_job / "summary.json"
    guest_outputs_zip = guest_job / "memory-string-hits.zip"
    guest_run_log = guest_job / "guest-run.log"
    local_analyzer = Path(__file__).with_name("guest") / "memory_triage_guest.py"

    client.run_guest_script(f"set -eu\nmkdir -p {shlex.quote(str(guest_job))}\n")
    client.copy_to_guest(local_analyzer, guest_analyzer)
    command = [
        "python3",
        shlex.quote(str(guest_analyzer)),
        "--memory",
        shlex.quote(guest_memory_path),
        "--output-dir",
        shlex.quote(str(guest_job)),
    ]
    for term in terms:
        command.extend(["--term", shlex.quote(term)])
    client.run_guest_script(
        "set -eu\n"
        + f"{' '.join(command)} > {shlex.quote(str(guest_run_log))} 2>&1\n"
    )

    summary_path = output_dir / "summary.json"
    client.copy_from_guest(guest_summary, summary_path)
    client.copy_from_guest(guest_outputs_zip, output_dir / "memory-string-hits.zip")
    client.copy_from_guest(guest_run_log, output_dir / "guest-run.log")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    write_memory_report(summary, output_dir / "report.md")
    return {
        "status": "ok",
        "output_dir": str(output_dir),
        "report": str(output_dir / "report.md"),
        "summary": str(summary_path),
        "memory_hits": str(output_dir / "memory-string-hits.zip"),
        "evidence_unchanged": summary["evidence"]["unchanged"],
        "matched_terms": sum(1 for entry in summary["memory"]["hit_counts"] if entry["count"]),
    }


def triage_guest_userassist(
    *,
    config: SiftVmConfig,
    guest_zip_path: str,
    output_dir: Path,
) -> dict[str, object]:
    client = VmrunClient(config)
    client.ensure_running()
    output_dir.mkdir(parents=True, exist_ok=True)

    job_id = f"userassist-{uuid4().hex[:12]}"
    guest_job = PurePosixPath("/tmp/findevil-sift") / job_id
    guest_analyzer = guest_job / "userassist_triage_guest.py"
    guest_summary = guest_job / "summary.json"
    guest_outputs_zip = guest_job / "userassist-outputs.zip"
    guest_run_log = guest_job / "guest-run.log"
    local_analyzer = Path(__file__).with_name("guest") / "userassist_triage_guest.py"

    client.run_guest_script(f"set -eu\nmkdir -p {shlex.quote(str(guest_job))}\n")
    client.copy_to_guest(local_analyzer, guest_analyzer)
    command = " ".join(
        [
            "python3",
            shlex.quote(str(guest_analyzer)),
            "--zip",
            shlex.quote(guest_zip_path),
            "--output-dir",
            shlex.quote(str(guest_job)),
        ]
    )
    client.run_guest_script(
        "set -eu\n"
        f"{command} > {shlex.quote(str(guest_run_log))} 2>&1\n"
    )

    summary_path = output_dir / "summary.json"
    client.copy_from_guest(guest_summary, summary_path)
    client.copy_from_guest(guest_outputs_zip, output_dir / "userassist-outputs.zip")
    client.copy_from_guest(guest_run_log, output_dir / "guest-run.log")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    write_userassist_report(summary, output_dir / "report.md")
    return {
        "status": "ok",
        "output_dir": str(output_dir),
        "report": str(output_dir / "report.md"),
        "summary": str(summary_path),
        "userassist_outputs": str(output_dir / "userassist-outputs.zip"),
        "evidence_unchanged": summary["evidence"]["unchanged"],
        "execution_entries": summary["userassist"]["entry_count"],
        "review_candidates": len(summary["userassist"]["review_candidates"]),
    }


def inventory_guest_case(
    *,
    config: SiftVmConfig,
    guest_case_root: str,
    output_dir: Path,
) -> dict[str, object]:
    client = VmrunClient(config)
    client.ensure_running()
    output_dir.mkdir(parents=True, exist_ok=True)

    job_id = f"inventory-{uuid4().hex[:12]}"
    guest_job = PurePosixPath("/tmp/findevil-sift") / job_id
    guest_analyzer = guest_job / "case_inventory_guest.py"
    guest_inventory = guest_job / "inventory.json"
    guest_run_log = guest_job / "guest-run.log"
    local_analyzer = Path(__file__).with_name("guest") / "case_inventory_guest.py"

    client.run_guest_script(f"set -eu\nmkdir -p {shlex.quote(str(guest_job))}\n")
    client.copy_to_guest(local_analyzer, guest_analyzer)
    command = " ".join(
        [
            "python3",
            shlex.quote(str(guest_analyzer)),
            "--case-root",
            shlex.quote(guest_case_root),
            "--output-dir",
            shlex.quote(str(guest_job)),
        ]
    )
    client.run_guest_script(
        "set -eu\n"
        f"{command} > {shlex.quote(str(guest_run_log))} 2>&1\n"
    )

    inventory_path = output_dir / "inventory.json"
    client.copy_from_guest(guest_inventory, inventory_path)
    client.copy_from_guest(guest_run_log, output_dir / "guest-run.log")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    write_case_inventory_report(inventory, output_dir / "report.md")
    return {
        "status": "ok",
        "case_root": inventory["case_root"],
        "output_dir": str(output_dir),
        "inventory": str(inventory_path),
        "report": str(output_dir / "report.md"),
        "guest_run_log": str(output_dir / "guest-run.log"),
        "candidate_count": inventory["scan"]["candidate_count"],
        "candidate_counts": inventory["candidate_counts"],
    }
