import unittest

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdatatype
import dns.zone

import corrupt_zone


ORIGIN = dns.name.from_text("example.")


class CorruptZoneTests(unittest.TestCase):
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