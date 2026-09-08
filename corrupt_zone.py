"""DNSSEC ゾーンを検証用に意図的に破損させる。"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Callable
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.util
import dns.zone
from cryptography.hazmat.primitives.asymmetric import rsa

IN = dns.rdataclass.IN
ZSK_ALGORITHM = 8

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
        description="DNSSEC ゾーンを dnssecvalidator 検証用に加工する"
    )
    parser.add_argument("-i", "--input", type=Path, required=True, help="入力するゾーン")
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
        "--zsk-private-key",
        type=Path,
        help="nsec-* モードで RRSIG を再生成する ZSK の .private ファイル",
    )
    parser.add_argument(
        "-s",
        "--increment-serial",
        action="store_true",
        help="SOA レコードの Serial をインクリメントする",
    )
    return parser.parse_args()


def make_absolute_name(text: str, origin: dns.name.Name) -> dns.name.Name:
    return dns.name.from_text(text, origin)


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


def decode_private_value(value: str) -> int:
    try:
        value += "=" * (-len(value) % 4)
        return int.from_bytes(base64.b64decode(value, validate=True), "big")
    except (ValueError, binascii.Error) as error:
        raise ValueError(".private ファイルの Base64 値を読み込めませんでした") from error


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            values[name.strip()] = value.strip()
        algorithm = int(values["Algorithm"].split("(", 1)[0].strip())
        if algorithm != ZSK_ALGORITHM:
            raise ValueError(
                f"対応する ZSK アルゴリズムは RSA/SHA-256 (8) だけです: {algorithm}"
            )
        numbers = rsa.RSAPrivateNumbers(
            p=decode_private_value(values["Prime1"]),
            q=decode_private_value(values["Prime2"]),
            d=decode_private_value(values["PrivateExponent"]),
            dmp1=decode_private_value(values["Exponent1"]),
            dmq1=decode_private_value(values["Exponent2"]),
            iqmp=decode_private_value(values["Coefficient"]),
            public_numbers=rsa.RSAPublicNumbers(
                e=decode_private_value(values["PublicExponent"]),
                n=decode_private_value(values["Modulus"]),
            ),
        )
        return numbers.private_key()
    except (KeyError, OSError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith("対応する"):
            raise
        raise ValueError(f"RSA 形式の .private ファイルを読み込めませんでした: {path}") from error


def find_zsk_dnskey(
    zone: dns.zone.Zone, algorithm: int, key_tag: int
) -> dns.rdata.Rdata:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    node = zone.get_node(zone.origin.relativize(zone.origin))
    if node is None:
        raise ValueError("ゾーン頂点の DNSKEY が見つかりません")
    for rdataset in node.rdatasets:
        if rdataset.rdclass != IN or rdataset.rdtype != dns.rdatatype.DNSKEY:
            continue
        for dnskey in rdataset:
            if dnskey.flags & 0x0100 and dnskey.algorithm == algorithm == ZSK_ALGORITHM:
                if dns.dnssec.key_id(dnskey) == key_tag:
                    return dnskey
    raise ValueError(
        f"対応する ZSK DNSKEY が見つかりません: algorithm={algorithm}, key_tag={key_tag}"
    )


def resign_denial_rrsets(
    zone: dns.zone.Zone,
    rdtype: dns.rdatatype.RdataType,
    key_path: Path,
    owners: set[dns.name.Name],
) -> int:
    private_key = load_private_key(key_path)
    changed = 0
    for owner, node in zone.nodes.items():
        if owner not in owners:
            continue
        denial_rdataset = next(
            (
                rdataset
                for rdataset in node.rdatasets
                if rdataset.rdclass == IN and rdataset.rdtype == rdtype
            ),
            None,
        )
        if denial_rdataset is None:
            continue
        rrsig_rdataset = None
        for candidate in node.rdatasets:
            if candidate.rdclass != IN or candidate.rdtype != dns.rdatatype.RRSIG:
                continue
            if any(rrsig_covers(rrsig, rdtype) for rrsig in candidate):
                rrsig_rdataset = candidate
                break
        if rrsig_rdataset is None:
            continue
        template = next(
            (rrsig for rrsig in rrsig_rdataset if rrsig_covers(rrsig, rdtype)),
            None,
        )
        if template is None:
            continue
        dnskey = find_zsk_dnskey(zone, template.algorithm, template.key_tag)
        absolute_owner = owner.derelativize(zone.origin)  # pyright: ignore
        signature = dns.dnssec.sign(
            (absolute_owner, denial_rdataset),
            private_key,
            template.signer.derelativize(zone.origin),  # pyright: ignore
            dnskey,
            inception=template.inception,
            expiration=template.expiration,
            origin=zone.origin,
        )
        original = list(rrsig_rdataset)
        rrsig_rdataset.clear()
        for rrsig in original:
            if rrsig_covers(rrsig, rdtype) and rrsig.key_tag == template.key_tag:
                rrsig_rdataset.add(signature)
            else:
                rrsig_rdataset.add(rrsig)
        changed += 1
    return changed


def zone_names(zone: dns.zone.Zone) -> list[dns.name.Name]:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    return sorted(name.derelativize(zone.origin) for name in zone.nodes)


def node_types(zone: dns.zone.Zone, name: dns.name.Name) -> list[dns.rdatatype.RdataType]:
    relative_name = name.relativize(zone.origin)  # pyright: ignore
    node = zone.get_node(relative_name)
    if node is None:
        return []
    types = {
        rdataset.rdtype
        for rdataset in node.rdatasets
        if rdataset.rdclass == IN
        and rdataset.rdtype not in {dns.rdatatype.RRSIG, dns.rdatatype.NSEC3PARAM}
    }
    return sorted(types, key=int)


def add_rdataset(
    zone: dns.zone.Zone,
    owner: dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: dns.rdata.Rdata,
) -> None:
    relative_owner = owner.relativize(zone.origin)  # pyright: ignore
    node = zone.find_node(relative_owner, create=True)
    rdataset = dns.rdataset.Rdataset(IN, rdtype)
    rdataset.add(rdata)
    node.replace_rdataset(rdataset)


def generate_nsec_records(zone: dns.zone.Zone) -> int:
    names = zone_names(zone)
    if not names:
        return 0
    for index, owner in enumerate(names):
        next_name = names[(index + 1) % len(names)]
        types = [*node_types(zone, owner), dns.rdatatype.NSEC]
        rdata = dns.rdata.from_text(
            IN,
            dns.rdatatype.NSEC,
            f"{next_name.to_text()} {' '.join(dns.rdatatype.to_text(rdtype) for rdtype in types)}",
            zone.origin,
        )
        add_rdataset(zone, owner, dns.rdatatype.NSEC, rdata)
    return len(names)


def nsec3_parameters(zone: dns.zone.Zone) -> tuple[int, int, int, bytes]:
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    node = zone.get_node(zone.origin.relativize(zone.origin))
    if node is not None:
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.NSEC3PARAM:
                parameter = next(iter(rdataset))
                return parameter.algorithm, parameter.flags, parameter.iterations, parameter.salt
    return 1, 0, 0, b""


def generate_nsec3_records(zone: dns.zone.Zone, flags: int = 0) -> int:
    names = zone_names(zone)
    algorithm, _parameter_flags, iterations, salt = nsec3_parameters(zone)
    if zone.origin is None:
        raise ValueError("ゾーンオリジンがありません")
    apex = zone.get_node(zone.origin.relativize(zone.origin))
    has_parameters = apex is not None and any(
        rdataset.rdtype == dns.rdatatype.NSEC3PARAM for rdataset in apex.rdatasets
    )
    if not has_parameters:
        salt_text = salt.hex().upper() if salt else "-"
        parameter = dns.rdata.from_text(
            IN,
            dns.rdatatype.NSEC3PARAM,
            f"{algorithm} 0 {iterations} {salt_text}",
            zone.origin,
        )
        add_rdataset(zone, zone.origin, dns.rdatatype.NSEC3PARAM, parameter)
    hashed_names = sorted(
        (
            dns.dnssec.nsec3_hash(name, salt, iterations, algorithm),
            name,
        )
        for name in names
    )
    if not hashed_names:
        return 0
    for index, (encoded_owner, original_name) in enumerate(hashed_names):
        next_owner = hashed_names[(index + 1) % len(hashed_names)][0]
        types = [*node_types(zone, original_name), dns.rdatatype.NSEC3]
        salt_text = salt.hex().upper() if salt else "-"
        rdata = dns.rdata.from_text(
            IN,
            dns.rdatatype.NSEC3,
            f"{algorithm} {flags} {iterations} {salt_text} {next_owner} "
            f"{' '.join(dns.rdatatype.to_text(rdtype) for rdtype in types)}",
            zone.origin,
        )
        owner = dns.name.from_text(f"{encoded_owner}.{zone.origin}")
        add_rdataset(zone, owner, dns.rdatatype.NSEC3, rdata)
    return len(hashed_names)


def ensure_denial_records(zone: dns.zone.Zone, mode: str) -> int:
    rdtype = dns.rdatatype.NSEC3 if mode.startswith("nsec3-") else dns.rdatatype.NSEC
    if any(
        rdataset.rdtype == rdtype
        for node in zone.nodes.values()
        for rdataset in node.rdatasets
    ):
        return 0
    if rdtype == dns.rdatatype.NSEC3:
        return generate_nsec3_records(zone, flags=1 if mode == "nsec3-optout-cover-mismatch" else 0)
    return generate_nsec_records(zone)


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


def denial_rrset_snapshot(
    zone: dns.zone.Zone, rdtype: dns.rdatatype.RdataType
) -> dict[dns.name.Name, tuple[str, ...]]:
    return {
        owner: tuple(
            sorted(
                rdata.to_text(origin=zone.origin)
                for rdataset in node.rdatasets
                if rdataset.rdclass == IN and rdataset.rdtype == rdtype
                for rdata in rdataset
            )
        )
        for owner, node in zone.nodes.items()
        if any(
            rdataset.rdclass == IN and rdataset.rdtype == rdtype
            for rdataset in node.rdatasets
        )
    }


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
        denial_type = (
            dns.rdatatype.NSEC3 if args.mode.startswith("nsec3-") else dns.rdatatype.NSEC
        )
        before_denial = (
            denial_rrset_snapshot(zone, denial_type) if args.mode.startswith("nsec") else {}
        )
        changed = modify_child_zone(zone, args.mode, args.target_name, target_type)
        if args.mode.startswith("nsec") and changed:
            if args.zsk_private_key is None:
                raise SystemExit("nsec-* モードでは --zsk-private-key が必要です")
            after_denial = denial_rrset_snapshot(zone, denial_type)
            changed_owners = {
                owner
                for owner, records in after_denial.items()
                if records != before_denial.get(owner)
            }
            try:
                resigned = resign_denial_rrsets(
                    zone, denial_type, args.zsk_private_key, changed_owners
                )
            except (OSError, ValueError, dns.exception.DNSException) as error:
                raise SystemExit(str(error)) from error
            if not resigned:
                raise SystemExit("変更対象 RRset の RRSIG が見つかりませんでした")

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
