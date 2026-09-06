#!/bin/sh
set -e

# 引数チェック
if [ -z "$1" ]; then
    echo "Usage: $0 <zone_file_name> [key_dir] [zone_dir]" >&2
    exit 1
fi

FILE_NAME="$1"
DOMAIN=`echo $1 | sed 's/.zone//g'`

# ディレクトリ定義
KEY_DIR="${2:-/usr/local/etc/nsd/keys}"
ZONE_DIR="${3:-/usr/local/etc/nsd/zone}"

# ファイルパス定義
ZONE_FILE="${ZONE_DIR}/${FILE_NAME}"
SIGNED_ZONE_FILE="${ZONE_FILE}.signed"

# ゾーンファイルの存在確認
if [ ! -f "$ZONE_FILE" ]; then
    echo "Error: Zone file not found: $ZONE_FILE" >&2
    exit 1
fi

# 鍵ファイルの特定とKSK/ZSKの判定
KSK_BASE=""
ZSK_BASE=""

for keyfile in "${KEY_DIR}"/K"${DOMAIN}".+*.key; do
    # 該当する鍵がない場合のプレースホルダ展開をスキップ
    [ -f "$keyfile" ] || continue
    
    # DNSKEYのキーワードの直後にあるフラグ値を取得
    flags=$(awk '{
        for(i=1; i<=NF; i++) {
            if($i == "DNSKEY") {
                print $(i+1);
                exit;
            }
        }
    }' "$keyfile")
    
    base_name="${keyfile%.key}"
    
    if [ "$flags" = "257" ]; then
        KSK_BASE="$base_name"
    elif [ "$flags" = "256" ]; then
        ZSK_BASE="$base_name"
    fi
done

# 鍵の存在チェック
if [ -z "$KSK_BASE" ] || [ -z "$ZSK_BASE" ]; then
    echo "Error: KSK (257) or ZSK (256) not found for $DOMAIN in $KEY_DIR" >&2
    exit 1
fi

# 署名の実行
ldns-signzone -f "$SIGNED_ZONE_FILE" "$ZONE_FILE" "$ZSK_BASE" "$KSK_BASE"

echo "Success: Signed zone file created at $SIGNED_ZONE_FILE"
