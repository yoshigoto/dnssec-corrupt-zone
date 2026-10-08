#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
	printf 'Usage: %s <base zone file name>\n' "$0" >&2
	exit 1
fi

base_zone_file=$1
template_file="template.algorithm.$base_zone_file"

if [ ! -f "$template_file" ]; then
	printf 'Template file not found: %s\n' "$template_file" >&2
	exit 1
fi

signing_algorithms="rsasha256 ecdsap256sha256 ed25519 ed448"
for algorithm in $signing_algorithms; do
	success_file="success.$algorithm.$base_zone_file"
	printf 'Creating %s\n' "$success_file"
	sed "s/algorithm/$algorithm/g" "$template_file" > "$success_file"
	sed 's/success/keytag.ds.error/g' "$success_file" > "keytag.ds.error.$algorithm.$base_zone_file"
	sed 's/success/hash.ds.error/g' "$success_file" > "hash.ds.error.$algorithm.$base_zone_file"
	sed 's/success/sign.ds.error/g' "$success_file" > "sign.ds.error.$algorithm.$base_zone_file"
	sed 's/success/sign.dnskey.error/g' "$success_file" > "sign.dnskey.error.$algorithm.$base_zone_file"
	sed 's/success/expire.dnskey.error/g' "$success_file" > "expire.dnskey.error.$algorithm.$base_zone_file"
	sed 's/success/sign.a.error/g' "$success_file" > "sign.a.error.$algorithm.$base_zone_file"

	if [ "$algorithm" = "rsasha256" ]; then
		sed 's/success/cover.mismatch.nsec/g' "$success_file" > "cover.mismatch.nsec.$algorithm.$base_zone_file"
		sed 's/success/type.mismatch.nsec/g' "$success_file" > "type.mismatch.nsec.$algorithm.$base_zone_file"
		sed 's/success/cover.mismatch.nsec3/g' "$success_file" > "cover.mismatch.nsec3.$algorithm.$base_zone_file"
		sed 's/success/type.mismatch.nsec3/g' "$success_file" > "type.mismatch.nsec3.$algorithm.$base_zone_file"
		sed 's/success/optout.mismatch.nsec3/g' "$success_file" > "optout.mismatch.nsec3.$algorithm.$base_zone_file"
	fi
done
