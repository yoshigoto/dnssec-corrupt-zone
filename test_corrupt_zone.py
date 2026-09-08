import unittest

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdatatype
import dns.zone

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
    def _rdata_at(
        zone: dns.zone.Zone, owner: str, rdtype: dns.rdatatype.RdataType
    ) -> dns.rdata.Rdata:
        node = zone.nodes[dns.name.from_text(owner, None)]
        rdataset = next(item for item in node.rdatasets if item.rdtype == rdtype)
        return next(iter(rdataset))


if __name__ == "__main__":
    unittest.main()