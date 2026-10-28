#!/usr/bin/env python3
"""Generate MLDSA44 DNSSEC KSK/ZSK files in ldns-compatible format."""

import argparse
import base64
import os
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.name
from cryptography.hazmat.primitives.asymmetric import mldsa


ALGORITHM = dns.dnssec.MLDSA44
ALGORITHM_NAME = "MLDSA44"
DEFAULT_TTL = 300


def key_file_contents(
    origin: dns.name.Name,
    ttl: int,
    flags: int,
    private_key: mldsa.MLDSA44PrivateKey,
) -> tuple[str, str, str, str | None]:
    dnskey = dns.dnssec.make_dnskey(private_key.public_key(), ALGORITHM, flags=flags)
    key_tag = dns.dnssec.key_id(dnskey)
    base_name = f"K{origin.to_text()[:-1]}.+{ALGORITHM:03d}+{key_tag:05d}"
    public = f"{origin} {ttl} IN DNSKEY {dnskey.to_text()}\n"
    seed = base64.b64encode(private_key.private_bytes_raw()).decode("ascii")
    private = (
        "Private-key-format: v1.3\n"
        f"Algorithm: {ALGORITHM} ({ALGORITHM_NAME})\n"
        f"PrivateKey: {seed}\n"
    )
    ds = None
    if flags == 257:
        ds_rdata = dns.dnssec.make_ds(origin, dnskey, "SHA256")
        ds = f"{origin} {ttl} IN DS {ds_rdata.to_text()}\n"
    return base_name, public, private, ds


def write_exclusive(path: Path, contents: str, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(contents)
    except OSError:
        path.unlink(missing_ok=True)
        raise


def generate_keys(origin: dns.name.Name, key_directory: Path, ttl: int) -> list[Path]:
    generated: list[Path] = []
    try:
        for flags in (257, 256):
            while True:
                private_key = mldsa.MLDSA44PrivateKey.generate()
                base_name, public, private, ds = key_file_contents(
                    origin, ttl, flags, private_key
                )
                if (key_directory / f"{base_name}.key") not in generated:
                    break

            paths_and_contents = [
                (key_directory / f"{base_name}.key", public, 0o644),
                (key_directory / f"{base_name}.private", private, 0o600),
            ]
            if ds is not None:
                paths_and_contents.append(
                    (key_directory / f"{base_name}.ds", ds, 0o644)
                )
            for path, contents, mode in paths_and_contents:
                write_exclusive(path, contents, mode)
                generated.append(path)
    except (OSError, ValueError):
        for path in generated:
            path.unlink(missing_ok=True)
        raise
    return generated


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate MLDSA44 KSK and ZSK files for a DNS zone."
    )
    parser.add_argument("zone", help="Zone name (with or without a trailing dot)")
    parser.add_argument(
        "--key-directory",
        type=Path,
        default=Path("."),
        help="Directory for generated key files (default: current directory)",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=DEFAULT_TTL,
        help=f"DNSKEY and DS TTL (default: {DEFAULT_TTL})",
    )
    arguments = parser.parse_args()

    try:
        origin = dns.name.from_text(arguments.zone, origin=dns.name.root)
        if origin == dns.name.root:
            raise ValueError("Zone name must not be the DNS root")
        if not 0 <= arguments.ttl <= 0xFFFFFFFF:
            raise ValueError("TTL must be between 0 and 4294967295")
        arguments.key_directory.mkdir(parents=True, exist_ok=True)
        generated = generate_keys(origin, arguments.key_directory, arguments.ttl)
    except (dns.exception.DNSException, OSError, ValueError) as error:
        parser.error(str(error))

    for path in generated:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
