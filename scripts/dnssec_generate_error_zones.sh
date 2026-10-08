#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
	printf 'Usage: %s [base zone file name]\n' "$0" >&2
	exit 1
fi

base_zone_file=${1:-dnssec-check.jp.zone}
zone_origin=${base_zone_file%.zone}
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
key_directory=${DNSSEC_KEY_DIR:-../keys}

printf '\n%s\n' "Create the zone files from a template."
sh "$script_dir/dnssec_make_error_zonefiles.sh" "$base_zone_file"

printf '\n%s\n' "Sign the child zone files."
sh "$script_dir/dnssec_sign_child_zones.sh" "$base_zone_file" "$key_directory"

printf '\n%s\n' "Corrupt child-zone signatures."
sh "$script_dir/dnssec_corrupt_child_zone.sh" "$base_zone_file"

printf '\n%s\n' "Copy the parent zone template."
cp -p "template.$base_zone_file" "$base_zone_file"

printf '\n%s\n' "Change the DS Key Tag and hash value."
sh "$script_dir/dnssec_corrupt_parent_zone.sh" "$base_zone_file" ds-keytag-mismatch
sh "$script_dir/dnssec_corrupt_parent_zone.sh" "$base_zone_file" ds-hash-mismatch

printf '\n%s\n' "Sign the parent zone."
sh "$script_dir/dnssec_sign_zone.sh" "$base_zone_file" "$zone_origin" "$key_directory" .

printf '\n%s\n' "Corrupt the DS RRSIG signature data."
sh "$script_dir/dnssec_corrupt_parent_zone.sh" "$base_zone_file.signed" ds-rrsig-corrupt

printf '\n%s\n' "Create corrupted NSEC and NSEC3 cases."
sh "$script_dir/dnssec_nsec_corrupt_zone.sh" \
	"cover.mismatch.nsec.rsasha256.$base_zone_file" nsec-cover-mismatch \
	"$zone_origin" "$key_directory" .
sh "$script_dir/dnssec_nsec_corrupt_zone.sh" \
	"cover.mismatch.nsec3.rsasha256.$base_zone_file" nsec3-cover-mismatch \
	"$zone_origin" "$key_directory" .
sh "$script_dir/dnssec_nsec_corrupt_zone.sh" \
	"type.mismatch.nsec3.rsasha256.$base_zone_file" nsec3-type-bitmap-mismatch \
	"$zone_origin" "$key_directory" .
sh "$script_dir/dnssec_nsec_corrupt_zone.sh" \
	"type.mismatch.nsec.rsasha256.$base_zone_file" nsec-type-bitmap-mismatch \
	"$zone_origin" "$key_directory" .
