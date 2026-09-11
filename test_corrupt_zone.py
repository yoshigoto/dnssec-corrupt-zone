import unittest
import base64
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import patch

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdatatype
import dns.zone
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

import corrupt_zone


ORIGIN = dns.name.from_text("example.")


class CorruptZoneTests(unittest.TestCase):
    def test_relative_target_name_uses_zone_origin(self) -> None:
        self.assertEqual(
            corrupt_zone.make_absolute_name("www", ORIGIN),
            dns.name.from_text("www.example."),
        )

    def test_ds_keytag_mismatch(self) -> None:
        zone = dns.zone.from_text(
            "child 300 IN DS 1234 8 2 "
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(
            corrupt_zone.modify_parent_zone(
                zone, "ds-keytag-mismatch", "child.example."
            ),
            1,
        )

        ds = self._rdata_at(zone, "child", dns.rdatatype.DS)
        self.assertEqual(getattr(ds, "key_tag"), 1235)

    def test_ds_hash_mismatch(self) -> None:
        zone = dns.zone.from_text(
            "child 300 IN DS 1234 8 2 "
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )
        original_digest = getattr(self._rdata_at(zone, "child", dns.rdatatype.DS), "digest")

        self.assertEqual(
            corrupt_zone.modify_parent_zone(zone, "ds-hash-mismatch", "child.example."),
            1,
        )

        ds = self._rdata_at(zone, "child", dns.rdatatype.DS)
        self.assertEqual(getattr(ds, "digest"), corrupt_zone.change_last_byte(original_digest))

    def test_ds_rrsig_corrupt(self) -> None:
        zone = dns.zone.from_text(
            "child 300 IN RRSIG DS 8 2 300 20300101000000 20200101000000 1234 example. AQID\n"
            "child 300 IN RRSIG A 8 2 300 20300101000000 20200101000000 1234 example. BAUG",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )
        original_signature = getattr(
            self._rdata_at(zone, "child", dns.rdatatype.RRSIG), "signature"
        )

        self.assertEqual(
            corrupt_zone.modify_parent_zone(zone, "ds-rrsig-corrupt", "child.example."),
            1,
        )

        rrsig = self._rdata_at(zone, "child", dns.rdatatype.RRSIG)
        self.assertEqual(
            getattr(rrsig, "signature"), corrupt_zone.change_last_byte(original_signature)
        )

    def test_dnskey_rrsig_corrupt(self) -> None:
        zone = dns.zone.from_text(
            "@ 300 IN RRSIG DNSKEY 8 0 300 20300101000000 20200101000000 1234 example. AQID\n"
            "@ 300 IN RRSIG A 8 0 300 20300101000000 20200101000000 1234 example. BAUG",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )
        original_signature = getattr(
            self._rdata_at(zone, "@", dns.rdatatype.RRSIG), "signature"
        )

        self.assertEqual(
            corrupt_zone.modify_child_zone(
                zone, "dnskey-rrsig-corrupt", None, dns.rdatatype.A
            ),
            1,
        )

        rrsig = self._rdata_at(zone, "@", dns.rdatatype.RRSIG)
        self.assertEqual(
            getattr(rrsig, "signature"), corrupt_zone.change_last_byte(original_signature)
        )

    def test_dnskey_rrsig_expired(self) -> None:
        zone = dns.zone.from_text(
            "@ 300 IN RRSIG DNSKEY 8 0 300 20300101000000 20200101000000 1234 example. AQID",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(
            corrupt_zone.modify_child_zone(
                zone, "dnskey-rrsig-expired", None, dns.rdatatype.A
            ),
            1,
        )

        rrsig = self._rdata_at(zone, "@", dns.rdatatype.RRSIG)
        self.assertEqual(getattr(rrsig, "expiration"), corrupt_zone.EXPIRED_AT)

    def test_increment_zone_soa_serial(self) -> None:
        zone = dns.zone.from_text(
            "@ 300 IN SOA ns.example. hostmaster.example. 4294967295 3600 600 86400 300",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(corrupt_zone.increment_zone_soa(zone), 1)

        soa = self._rdata_at(zone, "@", dns.rdatatype.SOA)
        self.assertEqual(getattr(soa, "serial"), 0)

    def test_nsec_coverage_mismatch(self) -> None:
        zone = dns.zone.from_text(
            "a 300 IN NSEC z.example. A\nz 300 IN NSEC a.example. A",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(corrupt_zone.modify_nsec_coverage(zone, "m.example."), 1)

        nsec = self._rdata_at(zone, "a", dns.rdatatype.NSEC)
        self.assertEqual(getattr(nsec, "next"), dns.name.from_text("a.example."))

    def test_nsec_type_bitmap_mismatch(self) -> None:
        zone = dns.zone.from_text(
            "aaaa 300 IN NSEC z.example. AAAA\nz 300 IN NSEC aaaa.example. A",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(
            corrupt_zone.modify_nsec_type_bitmap(zone, "aaaa.example.", dns.rdatatype.A),
            1,
        )

        nsec = self._rdata_at(zone, "aaaa", dns.rdatatype.NSEC)
        self.assertTrue(corrupt_zone.bitmap_contains(nsec, dns.rdatatype.A))

    def test_nsec3_coverage_mismatch(self) -> None:
        zone = self._nsec3_coverage_zone(flags=0)

        self.assertEqual(corrupt_zone.modify_nsec3_coverage(zone, "missing.example."), 1)

        nsec3 = self._rdata_at(zone, "00000000000000000000000000000000", dns.rdatatype.NSEC3)
        self.assertEqual(getattr(nsec3, "next"), bytes(20))

    def test_nsec3_optout_coverage_mismatch_requires_optout(self) -> None:
        without_optout = self._nsec3_coverage_zone(flags=0)
        with_optout = self._nsec3_coverage_zone(flags=1)

        self.assertEqual(
            corrupt_zone.modify_nsec3_coverage(
                without_optout, "missing.example.", require_opt_out=True
            ),
            0,
        )
        self.assertEqual(
            corrupt_zone.modify_nsec3_coverage(
                with_optout, "missing.example.", require_opt_out=True
            ),
            1,
        )

    def test_nsec3_type_bitmap_mismatch(self) -> None:
        target_name = "aaaa.example."
        hashed_name = dns.dnssec.nsec3_hash(target_name, b"", 0, 1).lower()
        zone = dns.zone.from_text(
            f"{hashed_name} 300 IN NSEC3 1 0 0 - {hashed_name} AAAA",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(
            corrupt_zone.modify_nsec3_type_bitmap(zone, target_name, dns.rdatatype.A),
            1,
        )

        nsec3 = self._rdata_at(zone, hashed_name, dns.rdatatype.NSEC3)
        self.assertTrue(corrupt_zone.bitmap_contains(nsec3, dns.rdatatype.A))

    def test_generate_nsec_records_for_unsigned_zone(self) -> None:
        zone = dns.zone.from_text(
            "@ 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300\n"
            "@ 300 IN NS ns.example.\n"
            "www 300 IN AAAA 2001:db8::1",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(corrupt_zone.ensure_denial_records(zone, "nsec-cover-mismatch"), 2)
        self.assertEqual(
            corrupt_zone.modify_nsec_coverage(zone, "missing.example."), 1
        )
        self.assertEqual(
            len([node for node in zone.nodes.values() if any(
                rdataset.rdtype == dns.rdatatype.NSEC for rdataset in node.rdatasets
            )]),
            2,
        )

    def test_generate_nsec3_records_for_unsigned_zone(self) -> None:
        zone = dns.zone.from_text(
            "@ 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300\n"
            "@ 300 IN NS ns.example.\n"
            "www 300 IN AAAA 2001:db8::1",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

        self.assertEqual(corrupt_zone.ensure_denial_records(zone, "nsec3-cover-mismatch"), 2)
        self.assertEqual(
            corrupt_zone.modify_nsec3_coverage(zone, "missing.example."), 1
        )
        self.assertIsNotNone(
            next(
                rdataset
                for rdataset in zone.nodes[dns.name.empty].rdatasets
                if rdataset.rdtype == dns.rdatatype.NSEC3PARAM
            )
        )

    def test_resign_changed_nsec_rrset(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        dnskey = dns.dnssec.make_dnskey(private_key.public_key(), 8, flags=256)
        key_tag = dns.dnssec.key_id(dnskey)
        zone = dns.zone.from_text(
            f"@ 300 IN DNSKEY {dnskey.to_text()}\n"
            "a 300 IN NSEC z.example. A\n"
            "z 300 IN NSEC a.example. A\n"
            f"a 300 IN RRSIG NSEC 8 2 300 20300101000000 20200101000000 {key_tag} example. AQID",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )
        self.assertEqual(corrupt_zone.modify_nsec_coverage(zone, "m.example."), 1)
        original_signature = getattr(
            self._rdata_at(zone, "a", dns.rdatatype.RRSIG), "signature"
        )

        with NamedTemporaryFile(suffix=".private", delete=False) as key_file:
            key_file.write(self._ldns_private_file(private_key).encode("ascii"))
            key_path = Path(key_file.name)
        try:
            self.assertEqual(
                corrupt_zone.resign_denial_rrsets(
                    zone, dns.rdatatype.NSEC, key_path, {dns.name.from_text("a", None)}
                ),
                1,
            )
        finally:
            key_path.unlink()

        rrsig = self._rdata_at(zone, "a", dns.rdatatype.RRSIG)
        self.assertNotEqual(getattr(rrsig, "signature"), original_signature)
        node_owner = dns.name.from_text("a", None)
        owner = dns.name.from_text("a.example.")
        nsec_rdataset = next(
            rdataset
            for rdataset in zone.nodes[node_owner].rdatasets
            if rdataset.rdtype == dns.rdatatype.NSEC
        )
        rrsig_rdataset = next(
            rdataset
            for rdataset in zone.nodes[node_owner].rdatasets
            if rdataset.rdtype == dns.rdatatype.RRSIG
        )
        dnskey_rdataset = next(
            rdataset
            for rdataset in zone.nodes[dns.name.empty].rdatasets
            if rdataset.rdtype == dns.rdatatype.DNSKEY
        )
        dns.dnssec.validate(
            (owner, nsec_rdataset),
            (owner, rrsig_rdataset),
            {ORIGIN: dnskey_rdataset},
            origin=ORIGIN,
        )

    def test_find_ldns_signing_keys_uses_zone_file_name(self) -> None:
        with TemporaryDirectory() as directory:
            key_dir = Path(directory)
            ksk_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            zsk_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self._write_ldns_key_pair(key_dir, "example", ksk_private_key, flags=257)
            self._write_ldns_key_pair(key_dir, "example", zsk_private_key, flags=256)

            keys = corrupt_zone.find_ldns_signing_keys(
                key_dir, Path("example.zone"), ORIGIN
            )

        self.assertEqual(keys.ksk.flags, 257)
        self.assertEqual(keys.zsk.flags, 256)

    def test_sign_zone_with_ldns_keys(self) -> None:
        zone = dns.zone.from_text(
            "@ 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300\n"
            "@ 300 IN NS ns.example.\n"
            "ns 300 IN A 192.0.2.53\n"
            "www 300 IN A 192.0.2.1",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )
        with TemporaryDirectory() as directory:
            key_dir = Path(directory)
            self._write_ldns_key_pair(
                key_dir,
                "example",
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
                flags=257,
            )
            self._write_ldns_key_pair(
                key_dir,
                "example",
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
                flags=256,
            )

            self.assertEqual(
                corrupt_zone.sign_zone_with_ldns_keys(zone, Path("example.zone"), key_dir),
                2,
            )

        dnskey_rdataset = next(
            rdataset
            for rdataset in zone.nodes[dns.name.empty].rdatasets
            if rdataset.rdtype == dns.rdatatype.DNSKEY
        )
        soa_rdataset = next(
            rdataset
            for rdataset in zone.nodes[dns.name.empty].rdatasets
            if rdataset.rdtype == dns.rdatatype.SOA
        )
        rrsig_rdataset = next(
            rdataset
            for rdataset in zone.nodes[dns.name.empty].rdatasets
            if rdataset.rdtype == dns.rdatatype.RRSIG
            and any(corrupt_zone.rrsig_covers(rrsig, dns.rdatatype.SOA) for rrsig in rdataset)
        )
        dns.dnssec.validate(
            (ORIGIN, soa_rdataset),
            (ORIGIN, rrsig_rdataset),
            {ORIGIN: dnskey_rdataset},
            origin=ORIGIN,
        )

    def test_main_signs_then_corrupts_dnskey_rrsig(self) -> None:
        algorithms = [
            (8, lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            (13, lambda: ec.generate_private_key(ec.SECP256R1())),
            (15, lambda: ed25519.Ed25519PrivateKey.generate()),
            (16, lambda: ed448.Ed448PrivateKey.generate()),
        ]
        for alg, keygen in algorithms:
            with self.subTest(algorithm=alg):
                with TemporaryDirectory() as directory:
                    work_dir = Path(directory)
                    input_path = work_dir / "example.zone"
                    output_path = work_dir / f"example.dnskey-rrsig-corrupt.{alg}.zone.signed"
                    key_dir = work_dir / "keys"
                    key_dir.mkdir()
                    input_path.write_text(self._unsigned_zone_text(), encoding="ascii")
                    self._write_ldns_key_pair(
                        key_dir,
                        "example",
                        keygen(),
                        flags=257,
                        algorithm=alg,
                    )
                    self._write_ldns_key_pair(
                        key_dir,
                        "example",
                        keygen(),
                        flags=256,
                        algorithm=alg,
                    )

                    with patch(
                        "sys.argv",
                        [
                            "corrupt_zone.py",
                            "--input",
                            str(input_path),
                            "--output",
                            str(output_path),
                            "--origin",
                            "example.",
                            "--mode",
                            "dnskey-rrsig-corrupt",
                            "--key-directory",
                            str(key_dir),
                            "--sign-zone",
                        ],
                    ):
                        corrupt_zone.main()

                    zone = dns.zone.from_file(
                        str(output_path), origin=ORIGIN, relativize=False, check_origin=False
                    )

                dnskey_rdataset = next(
                    rdataset
                    for rdataset in zone.nodes[ORIGIN].rdatasets
                    if rdataset.rdtype == dns.rdatatype.DNSKEY
                )
                rrsig_rdataset = next(
                    rdataset
                    for rdataset in zone.nodes[ORIGIN].rdatasets
                    if rdataset.rdtype == dns.rdatatype.RRSIG
                    and any(corrupt_zone.rrsig_covers(rrsig, dns.rdatatype.DNSKEY) for rrsig in rdataset)
                )
                with self.assertRaises(dns.dnssec.ValidationFailure):
                    dns.dnssec.validate(
                        (ORIGIN, dnskey_rdataset),
                        (ORIGIN, rrsig_rdataset),
                        {ORIGIN: dnskey_rdataset},
                        origin=ORIGIN,
                    )

    def test_main_signs_then_corrupts_and_resigns_nsec(self) -> None:
        with TemporaryDirectory() as directory:
            work_dir = Path(directory)
            input_path = work_dir / "example.zone"
            output_path = work_dir / "example.nsec-cover.zone.signed"
            key_dir = work_dir / "keys"
            key_dir.mkdir()
            input_path.write_text(self._unsigned_zone_text(), encoding="ascii")
            self._write_ldns_key_pair(
                key_dir,
                "example",
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
                flags=257,
            )
            self._write_ldns_key_pair(
                key_dir,
                "example",
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
                flags=256,
            )

            with patch(
                "sys.argv",
                [
                    "corrupt_zone.py",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--origin",
                    "example.",
                    "--mode",
                    "nsec-cover-mismatch",
                    "--target-name",
                    "missing.example.",
                    "--key-directory",
                    str(key_dir),
                    "--sign-zone",
                ],
            ):
                corrupt_zone.main()

            zone = dns.zone.from_file(
                str(output_path), origin=ORIGIN, relativize=False, check_origin=False
            )

        dnskey_rdataset = next(
            rdataset
            for rdataset in zone.nodes[ORIGIN].rdatasets
            if rdataset.rdtype == dns.rdatatype.DNSKEY
        )
        for owner, node in zone.nodes.items():
            nsec_rdataset = next(
                (rdataset for rdataset in node.rdatasets if rdataset.rdtype == dns.rdatatype.NSEC),
                None,
            )
            if nsec_rdataset is None:
                continue
            absolute_owner = owner.derelativize(ORIGIN)
            if any(
                getattr(nsec, "next").derelativize(ORIGIN) == absolute_owner
                for nsec in nsec_rdataset
            ):
                rrsig_rdataset = next(
                    rdataset
                    for rdataset in node.rdatasets
                    if rdataset.rdtype == dns.rdatatype.RRSIG
                    and any(corrupt_zone.rrsig_covers(rrsig, dns.rdatatype.NSEC) for rrsig in rdataset)
                )
                dns.dnssec.validate(
                    (absolute_owner, nsec_rdataset),
                    (absolute_owner, rrsig_rdataset),
                    {ORIGIN: dnskey_rdataset},
                    origin=ORIGIN,
                )
                return
        self.fail("壊れた NSEC レコードが見つかりませんでした")

    def test_load_private_key_all_supported_algorithms(self) -> None:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ed25519_key = ed25519.Ed25519PrivateKey.generate()
        ed448_key = ed448.Ed448PrivateKey.generate()

        with NamedTemporaryFile(suffix=".private", delete=False) as key_file:
            key_file.write(self._ldns_private_file(rsa_key, 8).encode("ascii"))
            rsa_path = Path(key_file.name)
        with NamedTemporaryFile(suffix=".private", delete=False) as key_file:
            key_file.write(self._ldns_private_file(ec_key, 13).encode("ascii"))
            ec_path = Path(key_file.name)
        with NamedTemporaryFile(suffix=".private", delete=False) as key_file:
            key_file.write(self._ldns_private_file(ed25519_key, 15).encode("ascii"))
            ed25519_path = Path(key_file.name)
        with NamedTemporaryFile(suffix=".private", delete=False) as key_file:
            key_file.write(self._ldns_private_file(ed448_key, 16).encode("ascii"))
            ed448_path = Path(key_file.name)

        try:
            loaded_rsa = corrupt_zone.load_private_key(rsa_path)
            loaded_ec = corrupt_zone.load_private_key(ec_path)
            loaded_ed25519 = corrupt_zone.load_private_key(ed25519_path)
            loaded_ed448 = corrupt_zone.load_private_key(ed448_path)

            self.assertIsInstance(loaded_rsa, rsa.RSAPrivateKey)
            self.assertIsInstance(loaded_ec, ec.EllipticCurvePrivateKey)
            self.assertIsInstance(loaded_ed25519, ed25519.Ed25519PrivateKey)
            self.assertIsInstance(loaded_ed448, ed448.Ed448PrivateKey)
        finally:
            rsa_path.unlink()
            ec_path.unlink()
            ed25519_path.unlink()
            ed448_path.unlink()

    def test_load_private_key_unsupported_algorithm(self) -> None:
        content = "Private-key-format: v1.2\nAlgorithm: 5 (RSASHA1)\n"
        with NamedTemporaryFile(suffix=".private", delete=False) as key_file:
            key_file.write(content.encode("ascii"))
            key_path = Path(key_file.name)
        try:
            with self.assertRaises(ValueError) as ctx:
                corrupt_zone.load_private_key(key_path)
            self.assertIn("対応していない鍵アルゴリズムです: 5", str(ctx.exception))
        finally:
            key_path.unlink()

    def test_sign_zone_and_resign_ecdsa_and_eddsa(self) -> None:
        algorithms = [
            (13, lambda: ec.generate_private_key(ec.SECP256R1())),
            (15, lambda: ed25519.Ed25519PrivateKey.generate()),
            (16, lambda: ed448.Ed448PrivateKey.generate()),
        ]
        for alg, keygen in algorithms:
            with self.subTest(algorithm=alg):
                zone = dns.zone.from_text(
                    "@ 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300\n"
                    "@ 300 IN NS ns.example.\n"
                    "ns 300 IN A 192.0.2.53\n"
                    "www 300 IN A 192.0.2.1",
                    origin=ORIGIN,
                    relativize=True,
                    check_origin=False,
                )
                with TemporaryDirectory() as directory:
                    key_dir = Path(directory)
                    self._write_ldns_key_pair(
                        key_dir,
                        "example",
                        keygen(),
                        flags=257,
                        algorithm=alg,
                    )
                    zsk = keygen()
                    self._write_ldns_key_pair(
                        key_dir,
                        "example",
                        zsk,
                        flags=256,
                        algorithm=alg,
                    )

                    self.assertEqual(
                        corrupt_zone.sign_zone_with_ldns_keys(
                            zone, Path("example.zone"), key_dir
                        ),
                        2,
                    )

                dnskey_rdataset = next(
                    rdataset
                    for rdataset in zone.nodes[dns.name.empty].rdatasets
                    if rdataset.rdtype == dns.rdatatype.DNSKEY
                )
                soa_rdataset = next(
                    rdataset
                    for rdataset in zone.nodes[dns.name.empty].rdatasets
                    if rdataset.rdtype == dns.rdatatype.SOA
                )
                rrsig_rdataset = next(
                    rdataset
                    for rdataset in zone.nodes[dns.name.empty].rdatasets
                    if rdataset.rdtype == dns.rdatatype.RRSIG
                    and any(corrupt_zone.rrsig_covers(rrsig, dns.rdatatype.SOA) for rrsig in rdataset)
                )
                dns.dnssec.validate(
                    (ORIGIN, soa_rdataset),
                    (ORIGIN, rrsig_rdataset),
                    {ORIGIN: dnskey_rdataset},
                    origin=ORIGIN,
                )

    def test_main_signs_then_corrupts_and_resigns_nsec_all_algorithms(self) -> None:
        algorithms = [
            (13, lambda: ec.generate_private_key(ec.SECP256R1())),
            (15, lambda: ed25519.Ed25519PrivateKey.generate()),
            (16, lambda: ed448.Ed448PrivateKey.generate()),
        ]
        for alg, keygen in algorithms:
            with self.subTest(algorithm=alg):
                with TemporaryDirectory() as directory:
                    work_dir = Path(directory)
                    input_path = work_dir / "example.zone"
                    output_path = work_dir / f"example.nsec-cover.{alg}.zone.signed"
                    key_dir = work_dir / "keys"
                    key_dir.mkdir()
                    input_path.write_text(self._unsigned_zone_text(), encoding="ascii")
                    self._write_ldns_key_pair(
                        key_dir,
                        "example",
                        keygen(),
                        flags=257,
                        algorithm=alg,
                    )
                    self._write_ldns_key_pair(
                        key_dir,
                        "example",
                        keygen(),
                        flags=256,
                        algorithm=alg,
                    )

                    with patch(
                        "sys.argv",
                        [
                            "corrupt_zone.py",
                            "--input",
                            str(input_path),
                            "--output",
                            str(output_path),
                            "--origin",
                            "example.",
                            "--mode",
                            "nsec-cover-mismatch",
                            "--target-name",
                            "missing.example.",
                            "--key-directory",
                            str(key_dir),
                            "--sign-zone",
                        ],
                    ):
                        corrupt_zone.main()

                    zone = dns.zone.from_file(
                        str(output_path), origin=ORIGIN, relativize=False, check_origin=False
                    )

                dnskey_rdataset = next(
                    rdataset
                    for rdataset in zone.nodes[ORIGIN].rdatasets
                    if rdataset.rdtype == dns.rdatatype.DNSKEY
                )
                found_corrupted = False
                for owner, node in zone.nodes.items():
                    nsec_rdataset = next(
                        (rdataset for rdataset in node.rdatasets if rdataset.rdtype == dns.rdatatype.NSEC),
                        None,
                    )
                    if nsec_rdataset is None:
                        continue
                    absolute_owner = owner.derelativize(ORIGIN)
                    if any(
                        getattr(nsec, "next").derelativize(ORIGIN) == absolute_owner
                        for nsec in nsec_rdataset
                    ):
                        rrsig_rdataset = next(
                            rdataset
                            for rdataset in node.rdatasets
                            if rdataset.rdtype == dns.rdatatype.RRSIG
                            and any(corrupt_zone.rrsig_covers(rrsig, dns.rdatatype.NSEC) for rrsig in rdataset)
                        )
                        dns.dnssec.validate(
                            (absolute_owner, nsec_rdataset),
                            (absolute_owner, rrsig_rdataset),
                            {ORIGIN: dnskey_rdataset},
                            origin=ORIGIN,
                        )
                        found_corrupted = True
                        break
                self.assertTrue(found_corrupted, f"アルゴリズム {alg} で壊れた NSEC レコードが見つかりませんでした")

    @staticmethod
    def _nsec3_coverage_zone(flags: int) -> dns.zone.Zone:
        return dns.zone.from_text(
            f"00000000000000000000000000000000 300 IN NSEC3 1 {flags} 0 - "
            "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV NS SOA RRSIG DNSKEY",
            origin=ORIGIN,
            relativize=True,
            check_origin=False,
        )

    @staticmethod
    def _unsigned_zone_text() -> str:
        return (
            "$ORIGIN example.\n"
            "@ 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300\n"
            "@ 300 IN NS ns.example.\n"
            "ns 300 IN A 192.0.2.53\n"
            "www 300 IN A 192.0.2.1\n"
        )

    @staticmethod
    def _ldns_private_file(private_key: corrupt_zone.PrivateKey, algorithm: int = 8) -> str:
        if algorithm == 8 and isinstance(private_key, rsa.RSAPrivateKey):
            numbers = private_key.private_numbers()

            def encode(value: int) -> str:
                raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
                return base64.b64encode(raw).decode("ascii").rstrip("=")

            return "\n".join(
                [
                    "Private-key-format: v1.3",
                    "Algorithm: 8 (RSASHA256)",
                    f"Modulus: {encode(numbers.public_numbers.n)}",
                    f"PublicExponent: {encode(numbers.public_numbers.e)}",
                    f"PrivateExponent: {encode(numbers.d)}",
                    f"Prime1: {encode(numbers.p)}",
                    f"Prime2: {encode(numbers.q)}",
                    f"Exponent1: {encode(numbers.dmp1)}",
                    f"Exponent2: {encode(numbers.dmq1)}",
                    f"Coefficient: {encode(numbers.iqmp)}",
                    "",
                ]
            )
        if algorithm == 13 and isinstance(private_key, ec.EllipticCurvePrivateKey):
            raw = private_key.private_numbers().private_value.to_bytes(32, "big")
            b64 = base64.b64encode(raw).decode("ascii")
            return "\n".join(
                [
                    "Private-key-format: v1.2",
                    "Algorithm: 13 (ECDSAP256SHA256)",
                    f"PrivateKey: {b64}",
                    "",
                ]
            )
        if algorithm == 15 and isinstance(private_key, ed25519.Ed25519PrivateKey):
            raw = private_key.private_bytes_raw()
            b64 = base64.b64encode(raw).decode("ascii")
            return "\n".join(
                [
                    "Private-key-format: v1.2",
                    "Algorithm: 15 (ED25519)",
                    f"PrivateKey: {b64}",
                    "",
                ]
            )
        if algorithm == 16 and isinstance(private_key, ed448.Ed448PrivateKey):
            raw = private_key.private_bytes_raw()
            b64 = base64.b64encode(raw).decode("ascii")
            return "\n".join(
                [
                    "Private-key-format: v1.2",
                    "Algorithm: 16 (ED448)",
                    f"PrivateKey: {b64}",
                    "",
                ]
            )
        raise ValueError(f"サポート外の鍵: {algorithm}, {type(private_key)}")

    @classmethod
    def _write_ldns_key_pair(
        cls, key_dir: Path, domain: str, private_key: corrupt_zone.PrivateKey, flags: int, algorithm: int = 8
    ) -> None:
        dnskey = dns.dnssec.make_dnskey(private_key.public_key(), algorithm, flags=flags)
        key_tag = dns.dnssec.key_id(dnskey)
        base_name = key_dir / f"K{domain}.+{algorithm:03d}+{key_tag:05d}"
        Path(f"{base_name}.key").write_text(
            f"{domain}. 300 IN DNSKEY {dnskey.to_text()}\n",
            encoding="ascii",
        )
        Path(f"{base_name}.private").write_text(
            cls._ldns_private_file(private_key, algorithm=algorithm),
            encoding="ascii",
        )

    @staticmethod
    def _rdata_at(
        zone: dns.zone.Zone, owner: str, rdtype: dns.rdatatype.RdataType
    ) -> dns.rdata.Rdata:
        node = zone.nodes[dns.name.from_text(owner, None)]
        rdataset = next(item for item in node.rdatasets if item.rdtype == rdtype)
        return next(iter(rdataset))


if __name__ == "__main__":
    unittest.main()