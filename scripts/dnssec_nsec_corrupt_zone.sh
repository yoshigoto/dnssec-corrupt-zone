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
target_type=A
nsec3_iterations=
nsec3_salt=

case "$mode" in
	nsec-cover-mismatch)
		target_name_prefix=missing
		add_target_type=0
		;;
	nsec-type-bitmap-mismatch)
		target_name_prefix=target
		add_target_type=1
		;;
	nsec3-cover-mismatch)
		target_name_prefix=missing
		add_target_type=0
		;;
	nsec3-type-bitmap-mismatch)
		target_name_prefix=target
		add_target_type=1
		;;
	nsec3-optout-cover-mismatch)
		target_name_prefix=unsigned
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

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
python=${PYTHON:-python3}

set -- -i "$zone_file" -o "$signed_zone_file" \
	-d "$zone_origin" -m "$mode" \
	--target-name "$target_name_prefix" \
	--key-directory "$key_directory" --sign-zone --sign-only
[ -z "$nsec3_iterations" ] || set -- "$@" --nsec3-iterations "$nsec3_iterations"
[ -z "$nsec3_salt" ] || set -- "$@" --nsec3-salt "$nsec3_salt"
"$python" "$script_dir/../corrupt_zone.py" "$@"

set -- -i "$signed_zone_file" -o "$signed_zone_file.out" \
	-d "$zone_origin" -m "$mode" \
	--target-name "$target_name_prefix" \
	--key-directory "$key_directory"
[ "$add_target_type" -ne 1 ] || set -- "$@" --target-type "$target_type"
"$python" "$script_dir/../corrupt_zone.py" "$@"

printf 'Signed zone file created at %s\n' "$signed_zone_file"
mv "$signed_zone_file" "$signed_zone_file.orig"
mv "$signed_zone_file.out" "$signed_zone_file"
