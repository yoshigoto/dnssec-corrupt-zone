#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ] || [ -z "$1" ] || [ -z "$2" ]; then
	printf 'Usage: %s <zone file name> <zone origin> [key directory] [zone directory]\n' "$0" >&2
	exit 1
fi

zone_file_name=$1
zone_origin=$2
key_directory=${3:-${DNSSEC_KEY_DIR:-../keys}}
zone_directory=${4:-${DNSSEC_ZONE_DIR:-.}}

zone_file="${zone_directory}/${zone_file_name}"
signed_zone_file="${zone_file}.signed"
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
python=${PYTHON:-python3}

if [ ! -f "$zone_file" ]; then
	printf 'Zone file not found: %s\n' "$zone_file" >&2
	exit 1
fi

"$python" "$script_dir/../corrupt_zone.py" \
	-i "$zone_file" -o "$signed_zone_file" \
	-d "$zone_origin" -m success \
	--key-directory "$key_directory" --sign-zone

printf 'Signed zone file created at %s\n' "$signed_zone_file"
