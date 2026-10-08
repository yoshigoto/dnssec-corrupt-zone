#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
	printf 'Usage: %s <base zone file name> [key directory]\n' "$0" >&2
	exit 1
fi

base_zone_file=$1
key_directory=${2:-${DNSSEC_KEY_DIR:-../keys}}
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
found_zone_file=0

for zone_file in *."$base_zone_file"; do
	[ -f "$zone_file" ] || continue
	found_zone_file=1
	printf '%s\n' "$zone_file"

	case "$zone_file" in
		"template.$base_zone_file"|"template.algorithm.$base_zone_file")
			printf 'Skip template: %s\n' "$zone_file"
			continue
			;;
	esac
	zone_origin=${zone_file%.zone}
	sh "$script_dir/dnssec_sign_zone.sh" "$zone_file" "$zone_origin" \
		"$key_directory" .
done

[ "$found_zone_file" -eq 1 ] || {
	printf 'Zone files not found for: %s\n' "$base_zone_file" >&2
	exit 1
}
