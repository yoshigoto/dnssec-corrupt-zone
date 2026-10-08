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

if [ ! -f "$zone_file" ]; then
	printf 'Zone file not found: %s\n' "$zone_file" >&2
	exit 1
fi

ksk_base=
zsk_base=

for key_file in "$key_directory"/K"$zone_origin".+*.key; do
	[ -f "$key_file" ] || continue

	flags=$(awk '{
		for (i = 1; i <= NF; i++) {
			if ($i == "DNSKEY") {
				print $(i + 1)
				exit
			}
		}
	}' "$key_file")

	key_base=${key_file%.key}
	case "$flags" in
		257) ksk_base=$key_base ;;
		256) zsk_base=$key_base ;;
	esac
done

if [ -z "$ksk_base" ] || [ -z "$zsk_base" ]; then
	printf 'KSK (257) or ZSK (256) not found for %s in %s\n' \
		"$zone_origin" "$key_directory" >&2
	exit 1
fi

ldns-signzone -f "$signed_zone_file" "$zone_file" "$zsk_base" "$ksk_base"

printf 'Signed zone file created at %s\n' "$signed_zone_file"
