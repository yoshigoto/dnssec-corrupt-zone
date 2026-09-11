#!/bin/sh
set -e

# 引数チェック
if [ -z "$1" ]; then
    echo "Usage: $0 <zone_file_name> [key_dir] [zone_dir]" >&2
    exit 1
fi

FILE_NAME="$1"
DOMAIN=${FILE_NAME%.signed}
DOMAIN=${DOMAIN%.zone}

# ディレクトリ定義
KEY_DIR="${2:-/etc/nsd/keys}"
ZONE_DIR="${3:-/etc/nsd/zones}"

# ファイルパス定義
ZONE_FILE="${ZONE_DIR}/${FILE_NAME}"
SIGNED_ZONE_FILE="${ZONE_FILE}.signed"

# ゾーンファイルの存在確認
if [ ! -f "$ZONE_FILE" ]; then
    echo "Error: Zone file not found: $ZONE_FILE" >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "${PYTHON:-}" ]; then
    if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
        PYTHON="$SCRIPT_DIR/.venv/bin/python"
    else
        PYTHON=python3
    fi
fi

"$PYTHON" "$SCRIPT_DIR/corrupt_zone.py" \
    --input "$ZONE_FILE" \
    --output "$SIGNED_ZONE_FILE" \
    --origin "${DOMAIN}." \
    --mode success \
    --sign-zone \
    --key-directory "$KEY_DIR"

echo "Success: Signed zone file created at $SIGNED_ZONE_FILE"
