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
    if arguments[0].endswith("dnssec_add_ds_records.py"):
        os.execv(sys.executable, [sys.executable, *arguments])
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
        (self.work_directory / f"template.{BASE_ZONE_FILE}").write_text(
            f"$ORIGIN {PARENT_ORIGIN}.\n"
            "$TTL 300\n"
            "@ IN SOA ns.example.test. hostmaster.example.test. "
            "(1 2h 1h 1w 1h)\n"
            "@ IN NS ns.example.test.\n"
            "success.rsasha256 IN NS ns.example.test.\n"
            "; EOF\n"
        )
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
            if flags == 257:
                Path(f"{key_base}.ds").write_text(
                    f"{origin}. IN DS {int(tag)} 8 2 {'00' * 32}\n"
                )

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
            if arguments[0].endswith("dnssec_add_ds_records.py"):
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

    def test_add_ds_records_requires_ds_file_for_each_delegation(self) -> None:
        zone_file = self.work_directory / BASE_ZONE_FILE
        zone_file.write_text(
            f"$ORIGIN {PARENT_ORIGIN}.\n"
            "$TTL 300\n"
            "@ IN SOA ns.example.test. hostmaster.example.test. "
            "(1 2h 1h 1w 1h)\n"
            "success.rsasha256 IN NS ns.example.test.\n"
            "; EOF\n"
        )

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "dnssec_add_ds_records.py"),
                str(zone_file),
                PARENT_ORIGIN,
                str(self.key_directory),
            ],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No DS files found", result.stderr)
        self.assertNotIn(" IN DS ", zone_file.read_text())

    def test_add_ds_records_is_idempotent(self) -> None:
        child_origin = f"success.rsasha256.{PARENT_ORIGIN}"
        zone_file = self.work_directory / BASE_ZONE_FILE
        zone_file.write_text(
            f"$ORIGIN {PARENT_ORIGIN}.\n"
            "$TTL 300\n"
            "@ IN SOA ns.example.test. hostmaster.example.test. "
            "(1 2h 1h 1w 1h)\n"
            "success.rsasha256 IN NS ns.example.test.\n"
            "; EOF\n"
        )
        (self.key_directory / f"K{child_origin}.+008+00001.ds").write_text(
            f"{child_origin}. IN DS 1 8 2 {'00' * 32}\n"
        )
        command = [
            sys.executable,
            str(SCRIPTS / "dnssec_add_ds_records.py"),
            str(zone_file),
            PARENT_ORIGIN,
            str(self.key_directory),
        ]

        first_run = subprocess.run(command, capture_output=True, text=True)
        second_run = subprocess.run(command, capture_output=True, text=True)

        self.assertEqual(first_run.returncode, 0, first_run.stderr)
        self.assertEqual(second_run.returncode, 0, second_run.stderr)
        self.assertIn("DS records added: 1", first_run.stdout)
        self.assertIn("DS records added: 0", second_run.stdout)
        self.assertEqual(zone_file.read_text().count(" IN DS "), 1)

    def test_generate_error_zones_preserves_parent_and_child_origins(self) -> None:
        self.prepare_child_zones()
        self.run_script("dnssec_generate_error_zones.sh", BASE_ZONE_FILE)
        parent_zone = self.work_directory / BASE_ZONE_FILE
        parent_contents = parent_zone.read_text()
        self.assertIn(
            "success.rsasha256.example.test. 300 IN DS 1 8 2 " + "00" * 32,
            parent_contents,
        )
        self.assertLess(parent_contents.index(" IN DS "), parent_contents.index("; EOF"))
        commands = self.commands()
        self.assertEqual(len(commands), 67)
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
