import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from findevil_sift.config import load_host_config
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
