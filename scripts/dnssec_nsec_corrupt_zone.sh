#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
	printf 'Usage: %s <zone file name> <mode> <zone origin> [key directory] [zone directory] [--target-type TYPE] [--nsec3-iterations COUNT] [--nsec3-salt HEX]\n' "$0" >&2
	exit 1
fi

zone_file_name=$1
mode=$2
zone_origin=$3
shift 3
use_optout=0
target_type=A
nsec3_iterations=
nsec3_salt=

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
	nsec3-type-bitmap-mismatch)
		target_name_prefix=target
		use_nsec3=1
		add_target_type=1
		;;
	nsec3-optout-cover-mismatch)
		target_name_prefix=unsigned
		use_nsec3=1
		use_optout=1
		add_target_type=0
		;;
	*)
		printf 'Invalid mode: %s\n' "$mode" >&2
		exit 1
		;;
esac

key_directory=${DNSSEC_KEY_DIR:-../keys}
zone_directory=${DNSSEC_ZONE_DIR:-.}
if [ "$#" -gt 0 ] && [ "${1#--}" = "$1" ]; then
	key_directory=$1
	shift
fi
if [ "$#" -gt 0 ] && [ "${1#--}" = "$1" ]; then
	zone_directory=$1
	shift
fi

while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-type|--nsec3-iterations|--nsec3-salt)
			[ "$#" -ge 2 ] && [ -n "$2" ] || {
				printf 'Missing value for %s\n' "$1" >&2
				exit 1
			}
			case "$1" in
				--target-type) target_type=$2 ;;
				--nsec3-iterations) nsec3_iterations=$2 ;;
				--nsec3-salt) nsec3_salt=$2 ;;
			esac
			shift 2
			;;
		*)
			printf 'Unknown option: %s\n' "$1" >&2
			exit 1
			;;
	esac
done

case "$nsec3_iterations" in
	''|*[!0-9]*)
		if [ -n "$nsec3_iterations" ]; then
			printf 'Invalid NSEC3 iteration count: %s\n' "$nsec3_iterations" >&2
			exit 1
		fi
		;;
esac
case "$nsec3_salt" in
	''|*[!0123456789abcdefABCDEF]*)
		if [ -n "$nsec3_salt" ]; then
			printf 'Invalid NSEC3 salt (expected hexadecimal): %s\n' "$nsec3_salt" >&2
			exit 1
		fi
		;;
esac
if [ $(( ${#nsec3_salt} % 2 )) -ne 0 ]; then
	printf 'Invalid NSEC3 salt (expected an even number of hexadecimal digits): %s\n' "$nsec3_salt" >&2
	exit 1
fi

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

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
python=${PYTHON:-python3}

if [ "$use_optout" -eq 1 ]; then
	set -- -i "$zone_file" -o "$signed_zone_file" \
		-d "$zone_origin" -t "$target_name_prefix" \
		--zsk-key-base "$zsk_base" --ksk-key-base "$ksk_base"
	[ -z "$nsec3_iterations" ] || set -- "$@" --nsec3-iterations "$nsec3_iterations"
	[ -z "$nsec3_salt" ] || set -- "$@" --nsec3-salt "$nsec3_salt"
	"$python" "$script_dir/dnssec_sign_optout_zone.py" "$@"
elif [ "$use_nsec3" -eq 1 ]; then
	set -- -n
	[ -z "$nsec3_iterations" ] || set -- "$@" -t "$nsec3_iterations"
	[ -z "$nsec3_salt" ] || set -- "$@" -s "$nsec3_salt"
	ldns-signzone "$@" "$zone_file" "$zsk_base" "$ksk_base"
else
	ldns-signzone "$zone_file" "$zsk_base" "$ksk_base"
fi

printf 'Signed zone file created at %s\n' "$signed_zone_file"

if [ "$add_target_type" -eq 1 ]; then
	"$python" "$script_dir/../corrupt_zone.py" \
		-i "$signed_zone_file" -o "$signed_zone_file.out" \
		-d "$zone_origin" -m "$mode" \
		--target-name "$target_name_prefix" \
		--zsk-private-key "$zsk_base.private" \
		--target-type "$target_type"
else
	"$python" "$script_dir/../corrupt_zone.py" \
		-i "$signed_zone_file" -o "$signed_zone_file.out" \
		-d "$zone_origin" -m "$mode" \
		--target-name "$target_name_prefix" \
		--zsk-private-key "$zsk_base.private"
fi
mv "$signed_zone_file" "$signed_zone_file.orig"
mv "$signed_zone_file.out" "$signed_zone_file"
