import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from findevil_sift.config import enforce_workflow_policy, load_host_config
from findevil_sift.vmware import SiftVmConfig


class HostConfigTests(TestCase):
    def test_loads_vm_paths_without_secrets(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "host.json"
            path.write_text(
                json.dumps({"sift_vm": {"vmx_path": "lab.vmx", "guest_user": "analyst"}}),
                encoding="utf-8",
            )

            config = load_host_config(path)

        self.assertEqual(config["sift_vm"]["vmx_path"], "lab.vmx")
        self.assertEqual(config["sift_vm"]["guest_user"], "analyst")

    def test_rejects_guest_password_in_host_config(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "host.json"
            path.write_text(
                json.dumps({"sift_vm": {"guest_password": "do-not-store-this"}}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must not store SIFT guest secrets"):
                load_host_config(path)

    def test_environment_overrides_host_config_and_password_stays_in_environment(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "host.json"
            path.write_text(
                json.dumps(
                    {
                        "sift_vm": {
                            "vmx_path": "configured.vmx",
                            "guest_user": "configured-user",
                            "vmrun_path": "configured-vmrun",
                        }
                    }
                ),
                encoding="utf-8",
            )

            with patch.dict(
                "os.environ",
                {
                    "SIFT_GUEST_PASSWORD": "secret-from-env",
                    "SIFT_GUEST_USER": "environment-user",
                    "SIFT_VMX_PATH": "environment.vmx",
                    "VMRUN_PATH": "environment-vmrun",
                },
                clear=True,
            ):
                config = SiftVmConfig.from_environment(host_config_path=path)

        self.assertEqual(config.guest_password, "secret-from-env")
        self.assertEqual(config.guest_user, "environment-user")
        self.assertEqual(config.vmx_path, Path("environment.vmx"))
        self.assertEqual(config.vmrun_path, Path("environment-vmrun"))

    def test_requires_vm_path_from_operator_configuration(self) -> None:
        with patch.dict("os.environ", {"SIFT_GUEST_PASSWORD": "secret-from-env"}, clear=True):
            with self.assertRaisesRegex(ValueError, "Set SIFT_VMX_PATH"):
                SiftVmConfig.from_environment()

    def test_operator_policy_resolves_relative_allowed_output_roots(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config" / "host.json"
            path.parent.mkdir()
            path.write_text(
                json.dumps(
                    {
                        "operator_policy": {
                            "allowed_output_roots": ["../case-outputs"],
                            "require_signed_run_manifests": True,
                        }
                    }
                ),
                encoding="utf-8",
            )

            config = load_host_config(path)

        self.assertEqual(
            config["operator_policy"]["allowed_output_roots"],
            [str((path.parent / "../case-outputs").resolve())],
        )
        self.assertTrue(config["operator_policy"]["require_signed_run_manifests"])

    def test_operator_policy_blocks_unsigned_or_out_of_root_workflow_outputs(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            path = root / "host.json"
            path.write_text(
                json.dumps(
                    {
                        "operator_policy": {
                            "allowed_output_roots": [str(allowed)],
                            "require_signed_run_manifests": True,
                        }
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "requires signed run manifests"):
                enforce_workflow_policy(
                    allowed / "case-a",
                    signing_key_present=False,
                    config_path=path,
                )
            with self.assertRaisesRegex(ValueError, "outside operator policy"):
                enforce_workflow_policy(
                    root / "outside" / "case-b",
                    signing_key_present=True,
                    config_path=path,
                )
            policy = enforce_workflow_policy(
                allowed / "case-c",
                signing_key_present=True,
                config_path=path,
            )

        self.assertTrue(policy["require_signed_run_manifests"])
