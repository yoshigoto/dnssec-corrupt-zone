#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
	printf 'Usage: %s <base zone name>\n' "$0" >&2
	exit 1
fi

base_zone_name=$1
template_file="template.$base_zone_name"

if [ ! -f "$template_file" ]; then
	printf 'Template file not found: %s\n' "$template_file" >&2
	exit 1
fi

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
project_dir=$(CDPATH= cd -P "$script_dir/.." && pwd)
python=${PYTHON:-python3}
key_directory=${DNSSEC_KEY_DIR:-../keys}
signing_algorithms="rsasha256 ecdsap256sha256 ed25519 ed448"

for algorithm in $signing_algorithms; do
	zone_file="sign.dnskey.error.$algorithm.$base_zone_name"
	zone_origin=${zone_file%.zone}
	printf 'Target: %s / %s\n' "$zone_file" "$zone_origin"
	"$python" "$project_dir/corrupt_zone.py" \
		-i "$zone_file" -o "$zone_file.signed" \
		-m dnskey-rrsig-corrupt -d "$zone_origin" \
		--sign-zone --key-directory "$key_directory"

	zone_file="expire.dnskey.error.$algorithm.$base_zone_name"
	zone_origin=${zone_file%.zone}
	printf 'Target: %s / %s\n' "$zone_file" "$zone_origin"
	"$python" "$project_dir/corrupt_zone.py" \
		-i "$zone_file" -o "$zone_file.signed" \
		-m dnskey-rrsig-expired -d "$zone_origin" \
		--sign-zone --key-directory "$key_directory"

	zone_file="sign.a.error.$algorithm.$base_zone_name"
	zone_origin=${zone_file%.zone}
	printf 'Target: %s / %s\n' "$zone_file" "$zone_origin"
	"$python" "$project_dir/corrupt_zone.py" \
		-i "$zone_file" -o "$zone_file.signed" \
		-m a-rrsig-corrupt -d "$zone_origin" \
		--sign-zone --key-directory "$key_directory" \
		--target-name corrupted
done
