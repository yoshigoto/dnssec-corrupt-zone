import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPTS = Path(__file__).resolve().parent / "scripts"
PARENT_ORIGIN = "example.test"
BASE_ZONE_FILE = f"{PARENT_ORIGIN}.zone"


class ShellScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory(prefix="dnssec scripts ")
        self.addCleanup(self.temporary_directory.cleanup)
        self.work_directory = Path(self.temporary_directory.name)
        self.key_directory = self.work_directory / "keys"
        self.key_directory.mkdir()
        self.command_directory = self.work_directory / "bin"
        self.command_directory.mkdir()
        self.log_file = self.work_directory / "commands.jsonl"
        stub = f"""#!{sys.executable}
import json
import os
from pathlib import Path
import shutil
import sys

arguments = sys.argv[1:]
command = Path(sys.argv[0]).name
with open(os.environ["COMMAND_LOG"], "a") as log:
    log.write(json.dumps([command, arguments]) + "\\n")
if command == "python-stub":
    shutil.copyfile(arguments[arguments.index("-i") + 1],
                    arguments[arguments.index("-o") + 1])
else:
    if "-f" in arguments:
        output_index = arguments.index("-f") + 1
        output = arguments[output_index]
        source = arguments[output_index + 1]
    else:
        source = next(argument for argument in arguments
                      if not argument.startswith("-"))
        output = source + ".signed"
    shutil.copyfile(source, output)
"""
        for command in ("python-stub", "ldns-signzone"):
            executable = self.command_directory / command
            executable.write_text(stub)
            executable.chmod(0o755)
        self.environment = {
            **os.environ,
            "PATH": f"{self.command_directory}{os.pathsep}{os.environ['PATH']}",
            "PYTHON": str(self.command_directory / "python-stub"),
            "DNSSEC_KEY_DIR": str(self.key_directory),
            "COMMAND_LOG": str(self.log_file),
        }
        (self.work_directory / f"template.{BASE_ZONE_FILE}").write_text("parent\n")
        (self.work_directory / f"template.algorithm.{BASE_ZONE_FILE}").write_text(
            "success.algorithm.example.test.\n"
        )

    def run_script(self, name: str, *arguments: str) -> None:
        result = subprocess.run(
            ["sh", str(SCRIPTS / name), *arguments],
            cwd=self.work_directory,
            env=self.environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def commands(self) -> list:
        return [json.loads(line) for line in self.log_file.read_text().splitlines()]

    def add_keys(self, origin: str) -> None:
        for flags, tag in ((257, "00001"), (256, "00002")):
            key_base = self.key_directory / f"K{origin}.+008+{tag}"
            Path(f"{key_base}.key").write_text(
                f"{origin}. IN DNSKEY {flags} 3 8 AQID\n"
            )
            Path(f"{key_base}.private").write_text("test stub key\n")

    def prepare_child_zones(self) -> None:
        self.run_script("dnssec_make_error_zonefiles.sh", BASE_ZONE_FILE)
        for zone_file in self.work_directory.glob(f"*.{BASE_ZONE_FILE}"):
            if not zone_file.name.startswith("template."):
                self.add_keys(zone_file.name.removesuffix(".zone"))
        self.add_keys(PARENT_ORIGIN)

    def assert_python_origins(self, commands: list) -> None:
        for command, arguments in commands:
            if command != "python-stub":
                continue
            source = Path(arguments[arguments.index("-i") + 1])
            expected_origin = source.name.removesuffix(".signed").removesuffix(".zone")
            self.assertEqual(arguments[arguments.index("-d") + 1], expected_origin)
            if "--zsk-private-key" in arguments:
                key = arguments[arguments.index("--zsk-private-key") + 1]
                self.assertEqual(
                    key, str(self.key_directory / f"K{expected_origin}.+008+00002.private")
                )

    def assert_signing_keys(self, commands: list) -> None:
        for command, arguments in commands:
            if command != "ldns-signzone":
                continue
            if "-f" in arguments:
                source = arguments[arguments.index("-f") + 2]
            else:
                source = next(value for value in arguments if not value.startswith("-"))
            expected_origin = Path(source).name.removesuffix(".zone")
            self.assertEqual(
                arguments[-2:],
                [
                    str(self.key_directory / f"K{expected_origin}.+008+00002"),
                    str(self.key_directory / f"K{expected_origin}.+008+00001"),
                ],
            )

    def test_corrupt_child_zone_passes_each_child_origin(self) -> None:
        self.prepare_child_zones()
        self.run_script("dnssec_corrupt_child_zone.sh", BASE_ZONE_FILE)
        commands = self.commands()
        self.assertEqual(len(commands), 12)
        self.assert_python_origins(commands)
        self.assertEqual(
            {arguments[arguments.index("-m") + 1] for _, arguments in commands},
            {"dnskey-rrsig-corrupt", "dnskey-rrsig-expired", "a-rrsig-corrupt"},
        )

    def test_sign_child_zones_selects_each_child_key(self) -> None:
        self.prepare_child_zones()
        self.run_script("dnssec_sign_child_zones.sh", BASE_ZONE_FILE)
        commands = self.commands()
        self.assertEqual(len(commands), 33)
        self.assert_signing_keys(commands)

    def test_make_error_zonefiles_replaces_all_algorithm_occurrences(self) -> None:
        (self.work_directory / f"template.algorithm.{BASE_ZONE_FILE}").write_text(
            "success.algorithm.example.test.\n"
            "ns.success.algorithm.example.test.\n"
        )

        self.run_script("dnssec_make_error_zonefiles.sh", BASE_ZONE_FILE)

        for algorithm in ("rsasha256", "ecdsap256sha256", "ed25519", "ed448"):
            zone_file = self.work_directory / f"success.{algorithm}.{BASE_ZONE_FILE}"
            contents = zone_file.read_text()
            self.assertIn(f"success.{algorithm}.example.test.", contents)
            self.assertIn(f"ns.success.{algorithm}.example.test.", contents)
            self.assertNotIn("algorithm", contents)

    def test_generate_error_zones_preserves_parent_and_child_origins(self) -> None:
        self.prepare_child_zones()
        self.run_script("dnssec_generate_error_zones.sh", BASE_ZONE_FILE)
        commands = self.commands()
        self.assertEqual(len(commands), 66)
        self.assert_python_origins(commands)
        self.assert_signing_keys(commands)
        for prefix in (
            "cover.mismatch.nsec",
            "cover.mismatch.nsec3",
            "type.mismatch.nsec3",
            "type.mismatch.nsec",
        ):
            signed_file = self.work_directory / f"{prefix}.rsasha256.{BASE_ZONE_FILE}.signed"
            self.assertTrue(signed_file.is_file())
            self.assertTrue(Path(f"{signed_file}.orig").is_file())


if __name__ == "__main__":
    unittest.main()
