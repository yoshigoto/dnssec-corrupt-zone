#!/usr/bin/env python3
"""Add DS records from ldns-key2ds output files to a parent zone."""

import argparse
import os
from pathlib import Path
import re
import stat
import tempfile

import dns.exception
import dns.name
import dns.rdatatype
import dns.zone


def parse_zone(path: Path, origin: dns.name.Name) -> dns.zone.Zone:
    try:
        return dns.zone.from_file(
            str(path),
            origin=origin,
            relativize=False,
            check_origin=False,
        )
    except (dns.exception.DNSException, OSError) as error:
        raise ValueError(f"Unable to parse zone file {path}: {error}") from error


def read_ds_records(
    ds_files: list[Path],
    delegation: dns.name.Name,
    parent_origin: dns.name.Name,
    default_ttl: str,
) -> dict[str, str]:
    records: dict[str, str] = {}

    for ds_file in ds_files:
        text = ds_file.read_text(encoding="utf-8")
        if not re.search(r"(?im)^[ \t]*\$TTL[ \t]", text):
            text = f"$TTL {default_ttl}\n{text}"
        try:
            zone = dns.zone.from_text(
                text,
                origin=parent_origin,
                relativize=False,
                check_origin=False,
                filename=str(ds_file),
            )
        except dns.exception.DNSException as error:
            raise ValueError(f"Unable to parse DS file {ds_file}: {error}") from error
        found_ds_record = False
        for owner, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                if rdataset.rdtype != dns.rdatatype.DS:
                    raise ValueError(
                        f"Unexpected {dns.rdatatype.to_text(rdataset.rdtype)} "
                        f"record in DS file {ds_file}"
                    )
                if owner != delegation:
                    raise ValueError(
                        f"DS owner {owner} in {ds_file} does not match "
                        f"delegation {delegation}"
                    )
                found_ds_record = True
                for rdata in rdataset:
                    text = rdata.to_text()
                    records[text] = (
                        f"{owner.to_text()} {rdataset.ttl} IN DS {text}"
                    )
        if not found_ds_record:
            raise ValueError(f"No DS records found in {ds_file}")

    return records


def existing_ds_records(
    zone: dns.zone.Zone,
    delegation: dns.name.Name,
) -> set[str]:
    node = zone.nodes.get(delegation)
    if node is None:
        return set()
    rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
    if rdataset is None:
        return set()
    return {rdata.to_text() for rdata in rdataset}


def insert_ds_records(zone_path: Path, records: list[str]) -> None:
    text = zone_path.read_text(encoding="utf-8")
    section = "\n; DS records (generated from key directory)\n"
    section += "\n".join(records) + "\n"

    eof_markers = list(
        re.finditer(r"(?im)^[ \t]*;[ \t]*EOF[ \t]*(?:\r?\n|$)", text)
    )
    if eof_markers:
        marker = eof_markers[-1]
        updated_text = text[: marker.start()] + section + text[marker.start() :]
    else:
        updated_text = text.rstrip("\r\n") + section

    file_mode = stat.S_IMODE(zone_path.stat().st_mode)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=zone_path.parent,
            prefix=f".{zone_path.name}.",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(updated_text)
        os.chmod(temporary_path, file_mode)
        os.replace(temporary_path, zone_path)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def add_ds_records(
    zone_path: Path,
    parent_origin: dns.name.Name,
    key_directory: Path,
) -> int:
    if not zone_path.is_file():
        raise ValueError(f"Zone file not found: {zone_path}")
    if not key_directory.is_dir():
        raise ValueError(f"Key directory not found: {key_directory}")

    zone = parse_zone(zone_path, parent_origin)
    zone_text = zone_path.read_text(encoding="utf-8")
    ttl_match = re.search(r"(?im)^[ \t]*\$TTL[ \t]+(\S+)", zone_text)
    if ttl_match is None:
        raise ValueError(f"Zone file must define $TTL to read DS files: {zone_path}")
    default_ttl = ttl_match.group(1)
    delegations = sorted(
        name
        for name, node in zone.nodes.items()
        if name != parent_origin
        and node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS) is not None
    )
    if not delegations:
        raise ValueError(f"No child-zone NS delegations found in {zone_path}")

    pending_records: list[str] = []
    for delegation in delegations:
        delegation_text = delegation.to_text()[:-1]
        ds_files = sorted(key_directory.glob(f"K{delegation_text}.+*.ds"))
        if not ds_files:
            raise ValueError(
                f"No DS files found for {delegation} in {key_directory} "
                f"(expected K{delegation_text}.+*.ds)"
            )

        expected = read_ds_records(
            ds_files, delegation, parent_origin, default_ttl
        )
        existing = existing_ds_records(zone, delegation)
        unexpected = existing - expected.keys()
        if unexpected:
            raise ValueError(
                f"Existing DS record(s) for {delegation} do not match "
                "the DS files: "
                + ", ".join(sorted(unexpected))
            )
        pending_records.extend(
            record
            for ds_text, record in sorted(expected.items())
            if ds_text not in existing
        )

    if pending_records:
        insert_ds_records(zone_path, pending_records)

    print(
        f"DS records added: {len(pending_records)} "
        f"({len(delegations)} delegations checked)"
    )
    return len(pending_records)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Add delegation DS records from ldns-key2ds .ds files."
    )
    parser.add_argument("zone_file", type=Path)
    parser.add_argument("zone_origin")
    parser.add_argument("key_directory", type=Path)
    arguments = parser.parse_args()

    origin_text = arguments.zone_origin
    if not origin_text.endswith("."):
        origin_text += "."

    try:
        origin = dns.name.from_text(origin_text, origin=dns.name.root)
        add_ds_records(arguments.zone_file, origin, arguments.key_directory)
    except (dns.exception.DNSException, OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
