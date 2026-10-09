#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
caller_directory=$(pwd -P)
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

zone_origin=${base_zone_file%.zone}

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

key_directory=${DNSSEC_KEY_DIR:-../keys}
if ! key_directory=$(CDPATH= cd -P "$key_directory" 2>/dev/null && pwd); then
	printf 'Key directory not found: %s\n' "${DNSSEC_KEY_DIR:-../keys}" >&2
	exit 1
fi
python=${PYTHON:-python3}
case "$python" in
	*/*)
		case "$python" in
			/*) ;;
			*) python="$caller_directory/$python" ;;
		esac
		;;
esac
PYTHON=$python
DNSSEC_KEY_DIR=$key_directory
export PYTHON DNSSEC_KEY_DIR

cd "$output_directory"

printf '\n%s\n' "Create the zone files from a template."
sh "$script_dir/dnssec_make_error_zonefiles.sh" \
	"$base_zone_file" --template-dir "$template_directory"

printf '\n%s\n' "Sign the child zone files."
sh "$script_dir/dnssec_sign_child_zones.sh" "$base_zone_file" "$key_directory"

printf '\n%s\n' "Corrupt child-zone signatures."
sh "$script_dir/dnssec_corrupt_child_zone.sh" \
	"$base_zone_file" "$template_directory"

printf '\n%s\n' "Copy the parent zone template."
cp -p "$template_directory/template.$base_zone_file" "$base_zone_file"

printf '\n%s\n' "Add child-zone DS records."
"$python" "$script_dir/dnssec_add_ds_records.py" \
	"$base_zone_file" "$zone_origin" "$key_directory"

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
	"cover.mismatch.nsec.rsasha256.$zone_origin" "$key_directory" .
sh "$script_dir/dnssec_nsec_corrupt_zone.sh" \
	"cover.mismatch.nsec3.rsasha256.$base_zone_file" nsec3-cover-mismatch \
	"cover.mismatch.nsec3.rsasha256.$zone_origin" "$key_directory" .
sh "$script_dir/dnssec_nsec_corrupt_zone.sh" \
	"type.mismatch.nsec3.rsasha256.$base_zone_file" nsec3-type-bitmap-mismatch \
	"type.mismatch.nsec3.rsasha256.$zone_origin" "$key_directory" .
sh "$script_dir/dnssec_nsec_corrupt_zone.sh" \
	"type.mismatch.nsec.rsasha256.$base_zone_file" nsec-type-bitmap-mismatch \
	"type.mismatch.nsec.rsasha256.$zone_origin" "$key_directory" .
