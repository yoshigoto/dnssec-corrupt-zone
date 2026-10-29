from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import dns.name

from scripts import dnssec_add_ds_records


PARENT_ORIGIN = dns.name.from_text("example.test.")
CHILD_ORIGIN = dns.name.from_text("child.example.test.")
FIRST_DS = f"1 8 2 {'11' * 32}"
SECOND_DS = f"2 8 2 {'22' * 32}"


class AddDSRecordsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.work_directory = Path(self.temporary_directory.name)
        self.zone_file = self.work_directory / "example.test.zone"
        self.key_directory = self.work_directory / "keys"
        self.key_directory.mkdir()

    def write_zone(
        self,
        delegations: tuple[str, ...] = ("child",),
        extra_records: str = "",
    ) -> str:
        text = (
            "$ORIGIN example.test.\n"
            "$TTL 300\n"
            "@ IN SOA ns.example.test. hostmaster.example.test. "
            "(1 2h 1h 1w 1h)\n"
            "@ IN NS ns.example.test.\n"
            + "".join(f"{name} IN NS ns.example.test.\n" for name in delegations)
            + extra_records
            + "; EOF\n"
        )
        self.zone_file.write_text(text, encoding="utf-8")
        return text

    def write_ds_file(
        self,
        child: str,
        key_tag: str,
        contents: str,
    ) -> Path:
        path = self.key_directory / f"K{child}.+008+{key_tag}.ds"
        path.write_text(contents, encoding="utf-8")
        return path

    def test_adds_rollover_records_before_eof_and_preserves_mode(self) -> None:
        original = self.write_zone()
        self.zone_file.chmod(0o640)
        self.write_ds_file(
            "child.example.test",
            "00001",
            f"$TTL 600\n{CHILD_ORIGIN} IN DS {FIRST_DS}\n",
        )
        self.write_ds_file(
            "child.example.test",
            "00002",
            f"{CHILD_ORIGIN} IN DS {SECOND_DS}\n",
        )

        added = dnssec_add_ds_records.add_ds_records(
            self.zone_file, PARENT_ORIGIN, self.key_directory
        )

        result = self.zone_file.read_text(encoding="utf-8")
        self.assertEqual(added, 2)
        self.assertIn(f"{CHILD_ORIGIN} 600 IN DS {FIRST_DS}\n", result)
        self.assertIn(f"{CHILD_ORIGIN} 300 IN DS {SECOND_DS}\n", result)
        self.assertLess(result.index(" IN DS "), result.index("; EOF"))
        self.assertTrue(result.endswith("; EOF\n"))
        self.assertEqual(self.zone_file.stat().st_mode & 0o777, 0o640)
        self.assertEqual(
            result.count("; DS records (generated from key directory)"), 1
        )
        self.assertTrue(result.startswith(original.split("; EOF")[0]))

    def test_rejects_invalid_ds_files_without_modifying_zone(self) -> None:
        invalid_files = (
            (
                "wrong owner",
                f"other.example.test. IN DS {FIRST_DS}\n",
                "does not match delegation",
            ),
            (
                "non-DS record",
                f"{CHILD_ORIGIN} IN NS ns.example.test.\n",
                "Unexpected NS record",
            ),
            ("no DS record", "; empty\n", "No DS records found"),
            (
                "malformed record",
                f"{CHILD_ORIGIN} IN DS invalid\n",
                "Unable to parse DS file",
            ),
        )

        for key_tag, (case, contents, error) in enumerate(invalid_files, start=1):
            with self.subTest(case=case):
                original = self.write_zone()
                for ds_file in self.key_directory.glob("*.ds"):
                    ds_file.unlink()
                self.write_ds_file(
                    "child.example.test", f"{key_tag:05d}", contents
                )

                with self.assertRaisesRegex(ValueError, error):
                    dnssec_add_ds_records.add_ds_records(
                        self.zone_file, PARENT_ORIGIN, self.key_directory
                    )

                self.assertEqual(
                    self.zone_file.read_text(encoding="utf-8"), original
                )

    def test_later_delegation_failure_does_not_partially_update_zone(self) -> None:
        original = self.write_zone(("alpha", "beta"))
        self.write_ds_file(
            "alpha.example.test",
            "00001",
            f"alpha.example.test. IN DS {FIRST_DS}\n",
        )
        self.write_ds_file(
            "beta.example.test",
            "00002",
            f"other.example.test. IN DS {SECOND_DS}\n",
        )

        with self.assertRaisesRegex(ValueError, "does not match delegation"):
            dnssec_add_ds_records.add_ds_records(
                self.zone_file, PARENT_ORIGIN, self.key_directory
            )

        self.assertEqual(self.zone_file.read_text(encoding="utf-8"), original)

    def test_existing_ds_not_in_files_is_rejected_without_modification(self) -> None:
        existing_ds = f"9 8 2 {'99' * 32}"
        original = self.write_zone(
            extra_records=f"{CHILD_ORIGIN} IN DS {existing_ds}\n"
        )
        self.write_ds_file(
            "child.example.test",
            "00001",
            f"{CHILD_ORIGIN} IN DS {FIRST_DS}\n",
        )

        with self.assertRaisesRegex(ValueError, "do not match the DS files"):
            dnssec_add_ds_records.add_ds_records(
                self.zone_file, PARENT_ORIGIN, self.key_directory
            )

        self.assertEqual(self.zone_file.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
