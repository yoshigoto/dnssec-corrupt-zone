"""署名済み DNSSEC ゾーンを検証用に意図的に破損させる。"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.zone

IN = dns.rdataclass.IN

MODES = {
    "success": "成功パターン: 署名済みゾーンをそのまま出力",
    "ds-keytag-mismatch": "親ゾーン: DS の Key Tag を不整合にする",
    "ds-hash-mismatch": "親ゾーン: DS の Digest を不整合にする",
    "ds-rrsig-corrupt": "親ゾーン: DS を覆う RRSIG を破損させる",
    "dnskey-rrsig-corrupt": "子ゾーン: DNSKEY を覆う RRSIG を破損させる",
    "dnskey-rrsig-expired": "子ゾーン: DNSKEY を覆う RRSIG を期限切れにする",
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
        help="親ゾーンで DS を変更する委任先名。--mode の ds-* では必須",
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


def modify_child_zone(zone: dns.zone.Zone, mode: str) -> int:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
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

    if args.mode == "success":
        changed = 0
    elif args.mode.startswith("ds-"):
        if not args.target_name:
            raise SystemExit("--mode の ds-* では --target-name が必要です")
        changed = modify_parent_zone(zone, args.mode, args.target_name)
    else:
        changed = modify_child_zone(zone, args.mode)

    if args.mode != "success" and not changed:
        raise SystemExit(f"対象レコードが見つかりませんでした: {MODES[args.mode]}")

    save_zone(zone, args.output, sorted_names=True, relativize=False, want_origin=True, chunksize=0)
    print(f"{MODES[args.mode]}: {args.output} (変更レコード数: {changed})")


if __name__ == "__main__":
    main()
