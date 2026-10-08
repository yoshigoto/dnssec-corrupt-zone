#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
	printf 'Usage: %s <zone file> <mode>\n' "$0" >&2
	exit 1
fi

zone_file=$1
mode="$2"
zone_origin=${zone_file%.signed}
zone_origin=${zone_origin%.zone}

case "$mode" in
	ds-keytag-mismatch) target_name_prefix=keytag.ds.error ;;
	ds-hash-mismatch) target_name_prefix=hash.ds.error ;;
	ds-rrsig-corrupt) target_name_prefix=sign.ds.error ;;
	*)
		printf 'Invalid mode: %s\n' "$mode" >&2
		exit 1
		;;
esac

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
python=${PYTHON:-python3}
temporary_file="$zone_file.out"
signing_algorithms="rsasha256 ecdsap256sha256 ed25519 ed448"

for algorithm in $signing_algorithms; do
	printf 'Target: %s / %s / %s.%s\n' \
		"$zone_file" "$zone_origin" "$target_name_prefix" "$algorithm"
	"$python" "$script_dir/corrupt_zone.py" \
		-i "$zone_file" -o "$temporary_file" \
		-m "$mode" -d "$zone_origin" \
		-t "$target_name_prefix.$algorithm"
	mv "$temporary_file" "$zone_file"
done
