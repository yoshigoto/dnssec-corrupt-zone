"""署名済み DNSSEC ゾーンを検証用に意図的に破損させる。"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Callable
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.util
import dns.zone

IN = dns.rdataclass.IN

MODES = {
    "success": "成功パターン: 署名済みゾーンをそのまま出力",
    "ds-keytag-mismatch": "親ゾーン: DS の Key Tag を不整合にする",
    "ds-hash-mismatch": "親ゾーン: DS の Digest を不整合にする",
    "ds-rrsig-corrupt": "親ゾーン: DS を覆う RRSIG を破損させる",
    "dnskey-rrsig-corrupt": "子ゾーン: DNSKEY を覆う RRSIG を破損させる",
    "dnskey-rrsig-expired": "子ゾーン: DNSKEY を覆う RRSIG を期限切れにする",
    "nsec-cover-mismatch": "子ゾーン: 指定名を覆う NSEC のカバー範囲を壊す",
    "nsec3-cover-mismatch": "子ゾーン: 指定名を覆う NSEC3 のカバー範囲を壊す",
    "nsec3-optout-cover-mismatch": "子ゾーン: Opt-Out NSEC3 のカバー範囲を壊す",
    "nsec-type-bitmap-mismatch": "子ゾーン: 指定名の NSEC 型ビットマップを不整合にする",
    "nsec3-type-bitmap-mismatch": "子ゾーン: 指定名の NSEC3 型ビットマップを不整合にする",
}
EXPIRED_AT = 1262304000  # 2010-01-01T00:00:00Z


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="署名済み DNSSEC ゾーンを dnssecvalidator 検証用に加工する"
    )
    parser.add_argument("-i", "--input", type=Path, required=True, help="入力する署名済みゾーン")
    parser.add_argument("-o", "--output", type=Path, required=True, help="出力するゾーン")
    parser.add_argument("-d", "--origin", required=True, help="ゾーンのオリジン (例: example.jp.)")
    parser.add_argument("-m", "--mode", required=True, choices=MODES, help="生成する検証ケース")
    parser.add_argument(
        "-t",
        "--target-name",
        help="加工対象の名前。--mode の ds-*、nsec-* では必須",
    )
    parser.add_argument(
        "--target-type",
        default="A",
        help="型ビットマップ不整合モードで追加する問い合わせ型 (既定: A)",
    )
    parser.add_argument(
        "-s",
        "--increment-serial",
        action="store_true",
        help="SOA レコードの Serial をインクリメントする",
    )
    return parser.parse_args()


def make_absolute_name(text: str, origin: dns.name.Name) -> dns.name.Name:
    name = dns.name.from_text(text)
    return name if name.is_absolute() else name.derelativize(origin)


def change_last_byte(value: bytes) -> bytes:
    if not value:
        raise ValueError("空のバイナリ値は破損できません")
    return value[:-1] + bytes([value[-1] ^ 0x01])


def replace_matching_rdatas(
    zone: dns.zone.Zone,
    owner: dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    predicate: Callable[[dns.rdata.Rdata], bool],
    replacement: Callable[[dns.rdata.Rdata], dns.rdata.Rdata],
) -> int:
    node = zone.get_node(owner)
    if node is None:
        return 0

    rdatasets = [
        rdataset
        for rdataset in node.rdatasets
        if rdataset.rdclass == IN and rdataset.rdtype == rdtype
    ]
    if not rdatasets:
        return 0

    changed = 0
    for rdataset in rdatasets:
        original = list(rdataset)
        matching = [predicate(rdata) for rdata in original]
        if any(matching):
            rdataset.clear()
            for rdata, matches in zip(original, matching):
                rdataset.add(replacement(rdata) if matches else rdata)
        changed += sum(matching)
    return changed


def rrsig_covers(rdata: dns.rdata.Rdata, covered_type: dns.rdatatype.RdataType) -> bool:
    return getattr(rdata, "type_covered", None) == covered_type


def alter_ds_key_tag(rdata: dns.rdata.Rdata) -> dns.rdata.Rdata:
    key_tag = getattr(rdata, "key_tag", None)
    if not isinstance(key_tag, int):
        raise TypeError("DS レコードではありません")
    return rdata.replace(key_tag=(key_tag + 1) % 65536)


def alter_ds_digest(rdata: dns.rdata.Rdata) -> dns.rdata.Rdata:
    digest = getattr(rdata, "digest", None)
    if not isinstance(digest, bytes):
        raise TypeError("DS レコードではありません")
    return rdata.replace(digest=change_last_byte(digest))


def alter_rrsig_signature(rdata: dns.rdata.Rdata) -> dns.rdata.Rdata:
    signature = getattr(rdata, "signature", None)
    if not isinstance(signature, bytes):
        raise TypeError("RRSIG レコードではありません")
    return rdata.replace(signature=change_last_byte(signature))


def expire_rrsig(rdata: dns.rdata.Rdata) -> dns.rdata.Rdata:
    return rdata.replace(expiration=EXPIRED_AT)


def increment_soa_serial(rdata: dns.rdata.Rdata) -> dns.rdata.Rdata:
    serial = getattr(rdata, "serial", None)
    if not isinstance(serial, int):
        raise TypeError("SOA レコードではありません")
    return rdata.replace(serial=(serial + 1) % (2**32))


def increment_zone_soa(zone: dns.zone.Zone) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    return replace_matching_rdatas(
        zone, zone.origin, dns.rdatatype.SOA, lambda _rdata: True, increment_soa_serial,
    )


def name_is_covered(
    owner: dns.name.Name, next_name: dns.name.Name, target: dns.name.Name
) -> bool:
    if owner < next_name:
        return owner < target < next_name
    if owner > next_name:
        return target > owner or target < next_name
    return False


def alter_nsec_coverage(rdata: dns.rdata.Rdata, owner: dns.name.Name) -> dns.rdata.Rdata:
    return rdata.replace(next=owner)


def nsec3_hash_from_owner(owner: dns.name.Name) -> bytes:
    encoded_hash = owner.labels[0].decode("ascii").upper()
    normal_base32 = encoded_hash.translate(
        str.maketrans("0123456789ABCDEFGHIJKLMNOPQRSTUV", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    )
    return base64.b32decode(normal_base32 + "=" * (-len(normal_base32) % 8))


def bitmap_rdtypes(windows: tuple[tuple[int, bytes], ...]) -> list[dns.rdatatype.RdataType]:
    rdtypes = []
    for window, bitmap in windows:
        for offset, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    rdtypes.append(dns.rdatatype.RdataType.make(window * 256 + offset * 8 + bit))
    return rdtypes


def bitmap_contains(rdata: dns.rdata.Rdata, target_type: dns.rdatatype.RdataType) -> bool:
    windows = getattr(rdata, "windows", None)
    if not isinstance(windows, tuple):
        raise TypeError("NSEC または NSEC3 レコードではありません")
    return target_type in bitmap_rdtypes(windows)


def add_type_to_bitmap(
    rdata: dns.rdata.Rdata, target_type: dns.rdatatype.RdataType
) -> dns.rdata.Rdata:
    windows = getattr(rdata, "windows", None)
    if not isinstance(windows, tuple):
        raise TypeError("NSEC または NSEC3 レコードではありません")
    windows = dns.rdtypes.util.Bitmap.from_rdtypes(
        [*bitmap_rdtypes(windows), target_type]
    ).windows
    return rdata.replace(windows=windows)


def modify_nsec_coverage(zone: dns.zone.Zone, target_name: str) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    target = make_absolute_name(target_name, zone.origin)
    for owner, node in zone.nodes.items():
        absolute_owner = owner.derelativize(zone.origin)
        for rdataset in node.rdatasets:
            if rdataset.rdclass != IN or rdataset.rdtype != dns.rdatatype.NSEC:
                continue
            original = list(rdataset)
            matching = [
                name_is_covered(absolute_owner, rdata.next, target) for rdata in original
            ]
            if any(matching):
                rdataset.clear()
                for rdata, matches in zip(original, matching):
                    rdataset.add(alter_nsec_coverage(rdata, absolute_owner) if matches else rdata)
                return sum(matching)
    return 0


def modify_nsec3_coverage(
    zone: dns.zone.Zone, target_name: str, require_opt_out: bool = False
) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    target = make_absolute_name(target_name, zone.origin)
    for owner, node in zone.nodes.items():
        absolute_owner = owner.derelativize(zone.origin)
        for rdataset in node.rdatasets:
            if rdataset.rdclass != IN or rdataset.rdtype != dns.rdatatype.NSEC3:
                continue
            original = list(rdataset)
            matching = [
                (
                    not require_opt_out or rdata.flags & 0x01
                )
                and name_is_covered(
                    absolute_owner,
                    rdata.next_name(zone.origin),
                    dns.name.from_text(
                        dns.dnssec.nsec3_hash(
                            target, rdata.salt, rdata.iterations, rdata.algorithm
                        ),
                        zone.origin,
                    ),
                )
                for rdata in original
            ]
            if any(matching):
                rdataset.clear()
                for rdata, matches in zip(original, matching):
                    rdataset.add(
                        rdata.replace(next=nsec3_hash_from_owner(absolute_owner))
                        if matches
                        else rdata
                    )
                return sum(matching)
    return 0


def modify_nsec_type_bitmap(
    zone: dns.zone.Zone, target_name: str, target_type: dns.rdatatype.RdataType
) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    owner = make_absolute_name(target_name, zone.origin)
    return replace_matching_rdatas(
        zone,
        owner,
        dns.rdatatype.NSEC,
        lambda rdata: not bitmap_contains(rdata, target_type),
        lambda rdata: add_type_to_bitmap(rdata, target_type),
    )


def modify_nsec3_type_bitmap(
    zone: dns.zone.Zone, target_name: str, target_type: dns.rdatatype.RdataType
) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    target = make_absolute_name(target_name, zone.origin)
    for owner, node in zone.nodes.items():
        absolute_owner = owner.derelativize(zone.origin)
        for rdataset in node.rdatasets:
            if rdataset.rdclass != IN or rdataset.rdtype != dns.rdatatype.NSEC3:
                continue
            original = list(rdataset)
            matching = [
                absolute_owner.labels[0].decode("ascii").upper()
                == dns.dnssec.nsec3_hash(target, rdata.salt, rdata.iterations, rdata.algorithm)
                and not bitmap_contains(rdata, target_type)
                for rdata in original
            ]
            if any(matching):
                rdataset.clear()
                for rdata, matches in zip(original, matching):
                    rdataset.add(add_type_to_bitmap(rdata, target_type) if matches else rdata)
                return sum(matching)
    return 0


def modify_parent_zone(zone: dns.zone.Zone, mode: str, target_name: str) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    owner = make_absolute_name(target_name, zone.origin)
    if mode == "ds-keytag-mismatch":
        return replace_matching_rdatas(
            zone, owner, dns.rdatatype.DS, lambda _rdata: True, alter_ds_key_tag,
        )
    if mode == "ds-hash-mismatch":
        return replace_matching_rdatas(
            zone, owner, dns.rdatatype.DS, lambda _rdata: True, alter_ds_digest,
        )
    return replace_matching_rdatas(
        zone, owner, dns.rdatatype.RRSIG,
        lambda rdata: rrsig_covers(rdata, dns.rdatatype.DS), alter_rrsig_signature,
    )


def modify_child_zone(
    zone: dns.zone.Zone,
    mode: str,
    target_name: str | None,
    target_type: dns.rdatatype.RdataType,
) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    if mode == "nsec-cover-mismatch":
        if target_name is None:
            raise ValueError("対象名がありません")
        return modify_nsec_coverage(zone, target_name)
    if mode == "nsec3-cover-mismatch":
        if target_name is None:
            raise ValueError("対象名がありません")
        return modify_nsec3_coverage(zone, target_name)
    if mode == "nsec3-optout-cover-mismatch":
        if target_name is None:
            raise ValueError("対象名がありません")
        return modify_nsec3_coverage(zone, target_name, require_opt_out=True)
    if mode == "nsec-type-bitmap-mismatch":
        if target_name is None:
            raise ValueError("対象名がありません")
        return modify_nsec_type_bitmap(zone, target_name, target_type)
    if mode == "nsec3-type-bitmap-mismatch":
        if target_name is None:
            raise ValueError("対象名がありません")
        return modify_nsec3_type_bitmap(zone, target_name, target_type)
    if mode == "dnskey-rrsig-corrupt":
        return replace_matching_rdatas(
            zone, zone.origin, dns.rdatatype.RRSIG,
            lambda rdata: rrsig_covers(rdata, dns.rdatatype.DNSKEY), alter_rrsig_signature,
        )
    return replace_matching_rdatas(
        zone, zone.origin, dns.rdatatype.RRSIG,
        lambda rdata: rrsig_covers(rdata, dns.rdatatype.DNSKEY), expire_rrsig,
    )


def save_zone(
    zone: dns.zone.Zone,
    output_path: Path,
    sorted_names: bool = True,
    relativize: bool = False,
    want_origin: bool = True,
    chunksize: int = 0,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        if want_origin and zone.origin is not None:
            f.write(f"$ORIGIN {zone.origin.to_text()}\n")
        names = list(zone.keys())
        if sorted_names:
            names.sort()
        for name in names:
            f.write(
                zone[name].to_text(
                    name,
                    origin=zone.origin,  # pyright: ignore
                    relativize=relativize,  # pyright: ignore
                    chunksize=chunksize,  # pyright: ignore
                )
            )
            f.write("\n")


def main() -> None:
    args = parse_args()
    origin = make_absolute_name(args.origin, dns.name.root)
    zone = dns.zone.from_file(str(args.input), origin=origin, relativize=True, check_origin=False)
    try:
        target_type = dns.rdatatype.from_text(args.target_type)
    except dns.exception.DNSException as error:
        raise SystemExit(f"不正な --target-type です: {args.target_type}") from error

    if args.mode == "success":
        changed = 0
    elif args.mode.startswith("ds-"):
        if not args.target_name:
            raise SystemExit("--mode の ds-* では --target-name が必要です")
        changed = modify_parent_zone(zone, args.mode, args.target_name)
    else:
        if args.mode.startswith("nsec") and not args.target_name:
            raise SystemExit("--mode の nsec-* では --target-name が必要です")
        changed = modify_child_zone(zone, args.mode, args.target_name, target_type)

    if args.mode != "success" and not changed:
        raise SystemExit(f"対象レコードが見つかりませんでした: {MODES[args.mode]}")

    if args.increment_serial:
        soa_changed = increment_zone_soa(zone)
        if not soa_changed:
            print("警告: SOA レコードが見つかりませんでした")
        else:
            print("SOA Serial をインクリメントしました")

    save_zone(zone, args.output, sorted_names=True, relativize=False, want_origin=True, chunksize=0)
    print(f"{MODES[args.mode]}: {args.output} (変更レコード数: {changed})")


if __name__ == "__main__":
    main()
