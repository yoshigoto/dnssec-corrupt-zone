#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
	printf 'Usage: %s <base zone file name> [key directory]\n' "$0" >&2
	exit 1
fi

base_zone_file=$1
zone_origin=${base_zone_file%.zone}
key_directory=${2:-${DNSSEC_KEY_DIR:-../keys}}
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
found_zone_file=0

for zone_file in *."$base_zone_file"; do
	[ -f "$zone_file" ] || continue
	found_zone_file=1
	printf '%s\n' "$zone_file"

	if [ "$zone_file" = "template.$base_zone_file" ]; then
		printf 'Skip template: %s\n' "$zone_file"
		continue
	fi
	sh "$script_dir/dnssec_sign_zone.sh" "$zone_file" "$zone_origin" \
		"$key_directory" .
done

[ "$found_zone_file" -eq 1 ] || {
	printf 'Zone files not found for: %s\n' "$base_zone_file" >&2
	exit 1
}
