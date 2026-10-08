#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 5 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
	printf 'Usage: %s <zone file name> <mode> <zone origin> [key directory] [zone directory]\n' "$0" >&2
	exit 1
fi

zone_file_name=$1
mode=$2
zone_origin=$3

case "$mode" in
	nsec-cover-mismatch)
		target_name_prefix=missing
		use_nsec3=0
		add_target_type=0
		;;
	nsec-type-bitmap-mismatch)
		target_name_prefix=target
		use_nsec3=0
		add_target_type=1
		;;
	nsec3-cover-mismatch)
		target_name_prefix=missing
		use_nsec3=1
		add_target_type=0
		;;
	nsec3-type-bitmap-mismatch|nsec3-optout-cover-mismatch)
		target_name_prefix=target
		use_nsec3=1
		add_target_type=1
		;;
	*)
		printf 'Invalid mode: %s\n' "$mode" >&2
		exit 1
		;;
esac

key_directory=${4:-${DNSSEC_KEY_DIR:-../keys}}
zone_directory=${5:-${DNSSEC_ZONE_DIR:-.}}

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

if [ "$use_nsec3" -eq 1 ]; then
	ldns-signzone -n -p "$zone_file" "$zsk_base" "$ksk_base"
else
	ldns-signzone "$zone_file" "$zsk_base" "$ksk_base"
fi

printf 'Signed zone file created at %s\n' "$signed_zone_file"

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
python=${PYTHON:-python3}

if [ "$add_target_type" -eq 1 ]; then
	"$python" "$script_dir/corrupt_zone.py" \
		-i "$signed_zone_file" -o "$signed_zone_file.out" \
		-d "$zone_origin" -m "$mode" \
		--target-name "$target_name_prefix" \
		--zsk-private-key "$zsk_base.private" \
		--target-type A
else
	"$python" "$script_dir/corrupt_zone.py" \
		-i "$signed_zone_file" -o "$signed_zone_file.out" \
		-d "$zone_origin" -m "$mode" \
		--target-name "$target_name_prefix" \
		--zsk-private-key "$zsk_base.private"
fi
mv "$signed_zone_file" "$signed_zone_file.orig"
mv "$signed_zone_file.out" "$signed_zone_file"
