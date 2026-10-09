#!/usr/bin/env python3
"""Sign an NSEC3 Opt-Out zone while omitting an unsigned delegation."""

import argparse
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.zone


def sign_optout_zone(
    input_path: Path,
    output_path: Path,
    origin: dns.name.Name,
    target: dns.name.Name,
    zsk_base: Path,
    ksk_base: Path,
    nsec3_iterations: int | None = None,
    nsec3_salt: str | None = None,
) -> None:
    zone = dns.zone.from_file(str(input_path), origin=origin, relativize=False)
    if target == origin or not target.is_subdomain(origin):
        raise ValueError(f"Opt-Out target must be a child delegation: {target}")
    node = zone.get_node(target)
    if node is None or node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS) is None:
        raise ValueError(f"Unsigned NS delegation not found: {target}")
    if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DS) is not None:
        raise ValueError(f"Opt-Out delegation must not have DS records: {target}")
    denial_types = {
        dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
        dns.rdatatype.NSEC3, dns.rdatatype.NSEC3PARAM,
    }
    if any(
        rdataset.rdtype in denial_types
        for node in zone.nodes.values()
        for rdataset in node.rdatasets
    ):
        raise ValueError("Opt-Out signing requires an unsigned input zone")

    delegation_nodes = {
        name: zone.nodes.pop(name)
        for name in list(zone.nodes)
        if name.is_subdomain(target)
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".optout-", dir=output_path.parent) as directory:
        prepared_path = Path(directory) / "prepared.zone"
        signed_path = Path(directory) / "prepared.zone.signed"
        # ldns -p sets flags but keeps unsigned-delegation hashes in the chain.
        zone.to_file(str(prepared_path), relativize=False, want_origin=True)
        command = [
            "ldns-signzone", "-n", "-p", "-f", str(signed_path),
        ]
        if nsec3_iterations is not None:
            command.extend(["-t", str(nsec3_iterations)])
        if nsec3_salt is not None:
            command.extend(["-s", nsec3_salt])
        command.extend([str(prepared_path), str(zsk_base), str(ksk_base)])
        subprocess.run(command, check=True)
        signed_zone = dns.zone.from_file(str(signed_path), origin=origin, relativize=False)
        signed_zone.nodes.update(delegation_nodes)
        signed_zone.to_file(str(signed_path), relativize=False, want_origin=True)
        os.replace(signed_path, output_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--input", type=Path, required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("-d", "--origin", required=True)
    parser.add_argument("-t", "--target-name", required=True)
    parser.add_argument("--zsk-key-base", type=Path, required=True)
    parser.add_argument("--ksk-key-base", type=Path, required=True)
    parser.add_argument("--nsec3-iterations", type=int)
    parser.add_argument("--nsec3-salt")
    args = parser.parse_args()
    try:
        if args.nsec3_iterations is not None and args.nsec3_iterations < 0:
            raise ValueError("NSEC3 iteration count must not be negative")
        if args.nsec3_salt is not None and (
            len(args.nsec3_salt) % 2
            or any(character not in "0123456789abcdefABCDEF" for character in args.nsec3_salt)
        ):
            raise ValueError("NSEC3 salt must be an even-length hexadecimal string")
        origin = dns.name.from_text(args.origin, dns.name.root)
        target = dns.name.from_text(args.target_name, origin)
        sign_optout_zone(
            args.input, args.output, origin, target,
            args.zsk_key_base, args.ksk_key_base,
            args.nsec3_iterations, args.nsec3_salt,
        )
    except (OSError, ValueError, dns.exception.DNSException, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
