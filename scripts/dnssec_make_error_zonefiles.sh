#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
template_directory="$script_dir/../templates"
output_directory=$(pwd -P)
base_zone_file=dnssec-check.jp.zone
base_zone_file_set=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--template-dir)
			[ "$#" -ge 2 ] && [ -n "$2" ] || {
				printf 'Missing directory for --template-dir\n' >&2
				exit 1
			}
			template_directory=$2
			shift 2
			;;
		--output-dir)
			[ "$#" -ge 2 ] && [ -n "$2" ] || {
				printf 'Missing directory for --output-dir\n' >&2
				exit 1
			}
			output_directory=$2
			shift 2
			;;
		--help|-h)
			printf 'Usage: %s [base zone file name] [--template-dir DIR] [--output-dir DIR]\n' "$0"
			exit 0
			;;
		-*)
			printf 'Unknown option: %s\n' "$1" >&2
			exit 1
			;;
		*)
			[ "$base_zone_file_set" -eq 0 ] || {
				printf 'Usage: %s [base zone file name] [--template-dir DIR] [--output-dir DIR]\n' "$0" >&2
				exit 1
			}
			base_zone_file=$1
			base_zone_file_set=1
			shift
			;;
	esac
done

if ! template_directory=$(CDPATH= cd -P "$template_directory" 2>/dev/null && pwd); then
	printf 'Template directory not found: %s\n' "$template_directory" >&2
	exit 1
fi
if ! mkdir -p "$output_directory"; then
	printf 'Unable to create output directory: %s\n' "$output_directory" >&2
	exit 1
fi
if ! output_directory=$(CDPATH= cd -P "$output_directory" && pwd); then
	printf 'Unable to access output directory\n' >&2
	exit 1
fi

template_file="$template_directory/template.algorithm.$base_zone_file"
if [ ! -f "$template_file" ]; then
	printf 'Template file not found: %s\n' "$template_file" >&2
	exit 1
fi
optout_template_file="$template_directory/template.optout.algorithm.$base_zone_file"
if [ ! -f "$optout_template_file" ]; then
	printf 'Template file not found: %s\n' "$optout_template_file" >&2
	exit 1
fi

cd "$output_directory"

signing_algorithms="rsasha256 ecdsap256sha256 ed25519 ed448"
for algorithm in $signing_algorithms; do
	success_file="success.$algorithm.$base_zone_file"
	printf 'Creating %s\n' "$success_file"
	sed "s/algorithm/$algorithm/g" "$template_file" > "$success_file"
	sed 's/success/keytag.ds.error/g' "$success_file" > "keytag.ds.error.$algorithm.$base_zone_file"
	sed 's/success/hash.ds.error/g' "$success_file" > "hash.ds.error.$algorithm.$base_zone_file"
	sed 's/success/sign.ds.error/g' "$success_file" > "sign.ds.error.$algorithm.$base_zone_file"
	sed 's/success/sign.dnskey.error/g' "$success_file" > "sign.dnskey.error.$algorithm.$base_zone_file"
	sed 's/success/expire.dnskey.error/g' "$success_file" > "expire.dnskey.error.$algorithm.$base_zone_file"
	sed 's/success/sign.a.error/g' "$success_file" > "sign.a.error.$algorithm.$base_zone_file"

	if [ "$algorithm" = "rsasha256" ]; then
		sed 's/success/cover.mismatch.nsec/g' "$success_file" > "cover.mismatch.nsec.$algorithm.$base_zone_file"
		sed 's/success/type.mismatch.nsec/g' "$success_file" > "type.mismatch.nsec.$algorithm.$base_zone_file"
		sed 's/success/cover.mismatch.nsec3/g' "$success_file" > "cover.mismatch.nsec3.$algorithm.$base_zone_file"
		sed 's/success/type.mismatch.nsec3/g' "$success_file" > "type.mismatch.nsec3.$algorithm.$base_zone_file"
		sed "s/algorithm/$algorithm/g" "$optout_template_file" > "optout.mismatch.nsec3.$algorithm.$base_zone_file"
	fi
done
