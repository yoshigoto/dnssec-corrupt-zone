import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.zone

import corrupt_zone


SCRIPTS = Path(__file__).resolve().parent / "scripts"
PARENT_ORIGIN = "example.test"
BASE_ZONE_FILE = f"{PARENT_ORIGIN}.zone"


class ShellScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory(prefix="dnssec scripts ")
        self.addCleanup(self.temporary_directory.cleanup)
        self.work_directory = Path(self.temporary_directory.name)
        self.template_directory = self.work_directory / "templates"
        self.template_directory.mkdir()
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
    if not Path(arguments[0]).is_file():
        sys.exit(f"Python script not found: {{arguments[0]}}")
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
                      if argument.endswith(".zone") and Path(argument).is_file())
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
        (self.template_directory / f"template.{BASE_ZONE_FILE}").write_text(
            f"$ORIGIN {PARENT_ORIGIN}.\n"
            "$TTL 300\n"
            "@ IN SOA ns.example.test. hostmaster.example.test. "
            "(1 2h 1h 1w 1h)\n"
            "@ IN NS ns.example.test.\n"
            "success.rsasha256 IN NS ns.example.test.\n"
            "; EOF\n"
        )
        (self.template_directory / f"template.algorithm.{BASE_ZONE_FILE}").write_text(
            "success.algorithm.example.test.\n"
        )
        (self.template_directory / f"template.optout.algorithm.{BASE_ZONE_FILE}").write_text(
            "$ORIGIN optout.mismatch.nsec3.algorithm.example.test.\n"
            "$TTL 300\n"
            "@ IN SOA ns.example.test. hostmaster.example.test. (1 2h 1h 1w 1h)\n"
            "@ IN NS ns.example.test.\n"
            "www IN A 192.0.2.1\n"
            "unsigned IN NS ns.example.test.\n"
        )

    def run_script(
        self, name: str, *arguments: str, cwd: Path | None = None
    ) -> None:
        result = subprocess.run(
            ["sh", str(SCRIPTS / name), *arguments],
            cwd=cwd or self.work_directory,
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
        self.run_script(
            "dnssec_make_error_zonefiles.sh",
            BASE_ZONE_FILE,
            "--template-dir",
            str(self.template_directory),
        )
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
            if arguments[0].endswith("dnssec_sign_optout_zone.py"):
                self.assertEqual(
                    Path(arguments[0]).resolve(), SCRIPTS / "dnssec_sign_optout_zone.py"
                )
                self.assertEqual(arguments[arguments.index("-t") + 1], "unsigned")
            else:
                self.assertEqual(
                    Path(arguments[0]).resolve(), SCRIPTS.parent / "corrupt_zone.py"
                )
            source = Path(arguments[arguments.index("-i") + 1])
            expected_origin = source.name.removesuffix(".signed").removesuffix(".zone")
            self.assertEqual(arguments[arguments.index("-d") + 1], expected_origin)
            for option, tag in (("--zsk-key-base", "00002"), ("--ksk-key-base", "00001")):
                if option in arguments:
                    self.assertEqual(
                        arguments[arguments.index(option) + 1],
                        str(self.key_directory / f"K{expected_origin}.+008+{tag}"),
                    )
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
                source = next(
                    value for value in arguments
                    if value.endswith(".zone")
                )
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
        self.run_script(
            "dnssec_corrupt_child_zone.sh",
            BASE_ZONE_FILE,
            str(self.template_directory),
        )
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
        self.assertEqual(len(commands), 46)
        self.assert_signing_keys(commands)

    def test_make_error_zonefiles_replaces_all_algorithm_occurrences(self) -> None:
        (self.template_directory / f"template.algorithm.{BASE_ZONE_FILE}").write_text(
            "success.algorithm.example.test.\n"
            "ns.success.algorithm.example.test.\n"
        )

        output_directory = self.work_directory / "generated zones"
        self.run_script(
            "dnssec_make_error_zonefiles.sh",
            BASE_ZONE_FILE,
            "--template-dir",
            str(self.template_directory),
            "--output-dir",
            str(output_directory),
        )

        for algorithm in ("rsasha256", "ecdsap256sha256", "ed25519", "ed448"):
            zone_file = output_directory / f"success.{algorithm}.{BASE_ZONE_FILE}"
            contents = zone_file.read_text()
            self.assertIn(f"success.{algorithm}.example.test.", contents)
            self.assertIn(f"ns.success.{algorithm}.example.test.", contents)
            self.assertNotIn("algorithm", contents)
        for zone_name in (
            "type.mx.mismatch.nsec.rsasha256",
            "type.txt.mismatch.nsec.rsasha256",
            "type.mx.mismatch.nsec3.rsasha256",
            "type.txt.mismatch.nsec3.rsasha256",
            "cover.mismatch.nsec3.iter0.saltA1B2.rsasha256",
            "type.mismatch.nsec3.iter1.nosalt.rsasha256",
            "optout.mismatch.nsec3.iter1.saltA1B2.rsasha256",
        ):
            contents = (output_directory / f"{zone_name}.{BASE_ZONE_FILE}").read_text()
            self.assertIn(f"{zone_name}.example.test.", contents)

    def test_make_optout_zone_has_unsigned_delegation(self) -> None:
        self.prepare_child_zones()
        origin = dns.name.from_text(f"optout.mismatch.nsec3.rsasha256.{PARENT_ORIGIN}.")
        zone = dns.zone.from_file(
            str(self.work_directory / f"{origin.to_text()[:-1]}.zone"),
            origin=origin, relativize=False,
        )
        target = dns.name.from_text("unsigned", origin)
        self.assertIsNotNone(zone.get_rdataset(target, dns.rdatatype.NS))
        self.assertIsNone(zone.get_rdataset(target, dns.rdatatype.DS))
        self.assertIsNone(zone.get_rdataset(target, dns.rdatatype.AAAA))

    def test_default_parent_delegates_all_generated_variations(self) -> None:
        output_directory = self.work_directory / "default zones"
        self.run_script(
            "dnssec_make_error_zonefiles.sh",
            "dnssec-check.jp.zone",
            "--output-dir",
            str(output_directory),
        )
        parent_origin = dns.name.from_text("dnssec-check.jp.")
        parent_template = dns.zone.from_file(
            str(SCRIPTS.parent / "templates" / "template.dnssec-check.jp.zone"),
            origin=parent_origin,
            relativize=False,
        )
        delegations = {
            owner for owner, node in parent_template.nodes.items()
            if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS) is not None
            and owner != parent_origin
        }
        generated_zones = list(output_directory.glob("*.dnssec-check.jp.zone"))
        self.assertTrue(generated_zones)
        for zone_file in generated_zones:
            child_origin = dns.name.from_text(
                zone_file.name.removesuffix(".zone") + "."
            )
            with self.subTest(zone=zone_file.name):
                self.assertIn(child_origin, delegations)
                dns.zone.from_file(
                    str(zone_file), origin=child_origin, relativize=False,
                )

    def test_make_error_zonefiles_requires_optout_template(self) -> None:
        (self.template_directory / f"template.optout.algorithm.{BASE_ZONE_FILE}").unlink()
        result = subprocess.run(
            ["sh", str(SCRIPTS / "dnssec_make_error_zonefiles.sh"), BASE_ZONE_FILE,
             "--template-dir", str(self.template_directory)],
            cwd=self.work_directory, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Template file not found:", result.stderr)
        self.assertIn("template.optout.algorithm.", result.stderr)
        self.assertFalse(list(self.work_directory.glob(f"*.{BASE_ZONE_FILE}")))

    def test_optout_signing_rejects_missing_delegation_or_ds(self) -> None:
        origin = dns.name.from_text(f"optout.mismatch.nsec3.rsasha256.{PARENT_ORIGIN}.")
        template = self.template_directory / f"template.optout.algorithm.{BASE_ZONE_FILE}"
        for records, target, message in [
            ("", "missing", "Unsigned NS delegation not found"),
            ("unsigned IN DS 1 8 2 " + "00" * 32 + "\n", "unsigned",
             "Opt-Out delegation must not have DS records"),
            ("", "outside.test.", "Opt-Out target must be a child delegation"),
        ]:
            with self.subTest(target=target, records=records):
                source = self.work_directory / "optout.zone"
                source.write_text(template.read_text().replace("algorithm", "rsasha256") + records)
                output = self.work_directory / "optout.zone.signed"
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / "dnssec_sign_optout_zone.py"),
                     "-i", str(source), "-o", str(output), "-d", origin.to_text(),
                     "-t", target, "--zsk-key-base", "unused", "--ksk-key-base", "unused"],
                    capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(output.exists())

    @unittest.skipUnless(
        shutil.which("ldns-keygen") and shutil.which("ldns-signzone"),
        "Real NSEC3 signing requires ldns-keygen and ldns-signzone",
    )
    def test_nsec3_signing_uses_iteration_and_salt_options(self) -> None:
        origin = dns.name.from_text(f"nsec3-params.{PARENT_ORIGIN}.")
        domain = origin.to_text()[:-1]
        source = self.work_directory / f"{domain}.zone"
        source.write_text(
            f"$ORIGIN {origin}\n"
            "$TTL 300\n"
            "@ IN SOA ns hostmaster (1 2h 1h 1w 1h)\n"
            "@ IN NS ns\n"
            "ns IN A 192.0.2.1\n"
            "www IN A 192.0.2.2\n"
        )
        for options in (["-k"], []):
            result = subprocess.run(
                ["ldns-keygen", "-a", "RSASHA256", "-b", "2048", *options, domain],
                cwd=self.key_directory, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        for iterations, salt in ((0, "A1B2"), (1, None), (1, "A1B2")):
            options = ["--nsec3-iterations", str(iterations)]
            if salt is not None:
                options.extend(["--nsec3-salt", salt])
            result = subprocess.run(
                ["sh", str(SCRIPTS / "dnssec_nsec_corrupt_zone.sh"),
                 source.name, "nsec3-cover-mismatch", domain,
                 str(self.key_directory), str(self.work_directory), *options],
                env={**os.environ, "PYTHON": sys.executable},
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            signed = dns.zone.from_file(
                f"{source}.signed.orig", origin=origin, relativize=False,
            )
            parameter = signed.get_rdataset(origin, dns.rdatatype.NSEC3PARAM)[0]
            self.assertEqual(parameter.iterations, iterations)
            self.assertEqual(parameter.salt, bytes.fromhex(salt) if salt else b"")

    @unittest.skipUnless(
        shutil.which("ldns-keygen") and shutil.which("ldns-signzone"),
        "Real Opt-Out signing requires ldns-keygen and ldns-signzone",
    )
    def test_optout_signing_omits_unsigned_hash_and_preserves_other_signatures(self) -> None:
        self.run_script(
            "dnssec_make_error_zonefiles.sh", BASE_ZONE_FILE,
            "--template-dir", str(self.template_directory),
        )
        origin = dns.name.from_text(f"optout.mismatch.nsec3.rsasha256.{PARENT_ORIGIN}.")
        domain = origin.to_text()[:-1]
        for options in (["-k"], []):
            result = subprocess.run(
                ["ldns-keygen", "-a", "RSASHA256", "-b", "2048", *options, domain],
                cwd=self.key_directory, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        source = self.work_directory / f"{domain}.zone"
        result = subprocess.run(
            ["sh", str(SCRIPTS / "dnssec_nsec_corrupt_zone.sh"),
             source.name, "nsec3-optout-cover-mismatch", domain,
             str(self.key_directory), str(self.work_directory)],
            env={**os.environ, "PYTHON": sys.executable},
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        original = dns.zone.from_file(f"{source}.signed.orig", origin=origin, relativize=False)
        modified = dns.zone.from_file(f"{source}.signed", origin=origin, relativize=False)
        target = dns.name.from_text("unsigned", origin)
        self.assertIsNotNone(original.get_rdataset(target, dns.rdatatype.NS))
        self.assertIsNone(original.get_rdataset(target, dns.rdatatype.DS))
        changes = []
        covering = []
        for owner, node in original.nodes.items():
            for rdataset in node.rdatasets:
                after = modified.nodes[owner].get_rdataset(
                    rdataset.rdclass, rdataset.rdtype, rdataset.covers
                )
                if rdataset != after:
                    changes.append((owner, rdataset.rdtype, rdataset.covers))
                if rdataset.rdtype == dns.rdatatype.NSEC3:
                    rdata = rdataset[0]
                    hashed_target = dns.name.from_text(
                        dns.dnssec.nsec3_hash(target, rdata.salt, rdata.iterations, rdata.algorithm),
                        origin,
                    )
                    self.assertNotIn(hashed_target, original.nodes)
                    if corrupt_zone.name_is_covered(owner, rdata.next_name(origin), hashed_target):
                        covering.append(owner)
                        self.assertEqual(rdata.flags & 1, 1)
                        self.assertEqual(after[0].next_name(origin), hashed_target)
                        self.assertEqual(after[0], rdata.replace(next=after[0].next))
                    self.assertFalse(
                        corrupt_zone.name_is_covered(owner, after[0].next_name(origin), hashed_target)
                    )
                if rdataset.rdtype != dns.rdatatype.RRSIG and owner != target:
                    signatures = modified.nodes[owner].get_rdataset(
                        rdataset.rdclass, dns.rdatatype.RRSIG, rdataset.rdtype
                    )
                    self.assertIsNotNone(signatures)
                    dns.dnssec.validate(
                        (owner, after), (owner, signatures),
                        {origin: modified.get_rdataset(origin, dns.rdatatype.DNSKEY)},
                        origin=origin,
                    )
        self.assertEqual(len(covering), 1)
        self.assertCountEqual(
            changes,
            [(covering[0], dns.rdatatype.NSEC3, dns.rdatatype.NONE),
             (covering[0], dns.rdatatype.RRSIG, dns.rdatatype.NSEC3)],
        )
        self.assertIsNone(modified.get_rdataset(target, dns.rdatatype.RRSIG))
        for iterations, salt in ((0, "A1B2"), (1, None), (1, "A1B2")):
            options = ["--nsec3-iterations", str(iterations)]
            if salt is not None:
                options.extend(["--nsec3-salt", salt])
            result = subprocess.run(
                ["sh", str(SCRIPTS / "dnssec_nsec_corrupt_zone.sh"),
                 source.name, "nsec3-optout-cover-mismatch", domain,
                 str(self.key_directory), str(self.work_directory), *options],
                env={**os.environ, "PYTHON": sys.executable},
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            signed = dns.zone.from_file(
                f"{source}.signed.orig", origin=origin, relativize=False,
            )
            parameter = signed.get_rdataset(origin, dns.rdatatype.NSEC3PARAM)[0]
            self.assertEqual(parameter.iterations, iterations)
            self.assertEqual(parameter.salt, bytes.fromhex(salt) if salt else b"")

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
        caller_directory = self.work_directory / "caller"
        caller_directory.mkdir()
        self.environment["DNSSEC_KEY_DIR"] = str(self.work_directory / "wrong-keys")
        self.run_script(
            "dnssec_generate_error_zones.sh",
            BASE_ZONE_FILE,
            "--key-dir",
            str(self.key_directory),
            "--template-dir",
            str(self.template_directory),
            "--output-dir",
            str(self.work_directory),
            cwd=caller_directory,
        )
        parent_zone = self.work_directory / BASE_ZONE_FILE
        parent_contents = parent_zone.read_text()
        self.assertIn(
            "success.rsasha256.example.test. 300 IN DS 1 8 2 " + "00" * 32,
            parent_contents,
        )
        self.assertLess(parent_contents.index(" IN DS "), parent_contents.index("; EOF"))
        commands = self.commands()
        self.assertEqual(len(commands), 108)
        self.assert_python_origins(commands)
        self.assert_signing_keys(commands)
        for prefix in (
            "cover.mismatch.nsec",
            "cover.mismatch.nsec3",
            "type.mismatch.nsec3",
            "type.mismatch.nsec",
            "optout.mismatch.nsec3",
            "type.mx.mismatch.nsec",
            "type.txt.mismatch.nsec",
            "type.mx.mismatch.nsec3",
            "type.txt.mismatch.nsec3",
        ):
            signed_file = self.work_directory / f"{prefix}.rsasha256.{BASE_ZONE_FILE}.signed"
            self.assertTrue(signed_file.is_file())
            self.assertTrue(Path(f"{signed_file}.orig").is_file())
        for profile in ("iter0.saltA1B2", "iter1.nosalt", "iter1.saltA1B2"):
            for prefix in (
                "cover.mismatch.nsec3",
                "type.mismatch.nsec3",
                "optout.mismatch.nsec3",
            ):
                signed_file = self.work_directory / (
                    f"{prefix}.{profile}.rsasha256.{BASE_ZONE_FILE}.signed"
                )
                self.assertTrue(signed_file.is_file())
                self.assertTrue(Path(f"{signed_file}.orig").is_file())
        bitmap_calls = [
            arguments for command, arguments in commands
            if command == "python-stub"
            and "-m" in arguments
            and arguments[arguments.index("-m") + 1].endswith("type-bitmap-mismatch")
        ]
        self.assertEqual(
            {
                arguments[arguments.index("--target-type") + 1]
                for arguments in bitmap_calls
            },
            {"A", "MX", "TXT"},
        )
        parent_template = (
            SCRIPTS.parent / "templates" / "template.dnssec-check.jp.zone"
        ).read_text()
        for profile in ("iter0.saltA1B2", "iter1.nosalt", "iter1.saltA1B2"):
            self.assertIn(f"cover.mismatch.nsec3.{profile}.rsasha256", parent_template)
        optout_calls = [
            arguments for command, arguments in commands
            if command == "python-stub"
            and "-m" in arguments
            and arguments[arguments.index("-m") + 1] == "nsec3-optout-cover-mismatch"
        ]
        self.assertEqual(len(optout_calls), 4)
        default_optout = next(
            arguments for arguments in optout_calls
            if "--nsec3-iterations" not in arguments
        )
        self.assertEqual(default_optout[default_optout.index("--target-name") + 1], "unsigned")
        self.assertNotIn("--target-type", default_optout)
        optout_sign_calls = [
            arguments for command, arguments in commands
            if command == "python-stub"
            and arguments[0].endswith("dnssec_sign_optout_zone.py")
        ]
        self.assertEqual(len(optout_sign_calls), 4)
        for profile, iterations, salt in (
            ("iter0.saltA1B2", "0", "A1B2"),
            ("iter1.nosalt", "1", None),
            ("iter1.saltA1B2", "1", "A1B2"),
        ):
            arguments = next(
                call for call in optout_sign_calls if profile in call[call.index("-d") + 1]
            )
            self.assertEqual(
                arguments[arguments.index("--nsec3-iterations") + 1],
                iterations,
            )
            if salt is None:
                self.assertNotIn("--nsec3-salt", arguments)
            else:
                self.assertEqual(arguments[arguments.index("--nsec3-salt") + 1], salt)


if __name__ == "__main__":
    unittest.main()
