# dnssec-corrupt-zone

DNSSEC ゾーンファイルを検証用に加工する Python スクリプトです。親ゾーンの `DS`、子ゾーンの `DNSKEY` と否定応答に使われる NSEC/NSEC3 を意図的に不整合にします。[DNSSEC委任状態検証ツール](https://www.on-link.jp/dnssec-validator/) で、実際に壊れた事例を確認することができます。

このツールは NSD の再読み込みを行いません。`--sign-zone` を指定すると、`ldns-keygen` 形式の鍵ファイルを使って dnspython でゾーン全体を署名します。`RRSIG` を破損するモードと `nsec-*` モードでは、署名後に対象レコードを壊します。`nsec-*` モードでは、指定された ZSK、または `--key-directory` から自動選択した ZSK で変更対象 NSEC/NSEC3 RRset の RRSIG だけを再生成します。必要に応じて署名前、または署名済みのゾーンファイルを用意し、このツールで出力されたゾーンファイルを NSD で読み込ませてください。

なお、本ツールで作成したドメイン名のリストを、[DNSSEC信頼の連鎖確認ページ](https://www.dnssec-check.jp/) で公開しています。

## 必要環境

- Python 3.10 以降
- `dnspython` 2.6 以降、3 未満
- `cryptography` 42 以降
- 親ゾーン・子ゾーンファイル (目的によって署名済みのもの、もしくは未署名のもの)

依存するモジュールをインストールします。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

`uv` を使用する場合は次のコマンドでもインストールできます。

```bash
uv venv
uv pip install --python .venv/bin/python -r requirements.txt
```

## 使い方

```text
.venv/bin/python corrupt_zone.py --input INPUT --output OUTPUT --origin ZONE_ORIGIN --mode MODE [--target-name NAME] [--target-type TYPE] [--zsk-private-key PRIVATE_FILE] [--key-directory KEY_DIR] [--sign-zone] [--increment-serial]
```

| 引数 | 説明 |
| --- | --- |
| `--input`, `-i` | 加工対象となるゾーンファイル |
| `--output`, `-o` | NSD に読み込ませる加工後のゾーンファイル |
| `--origin`, `-d` | 入力ゾーンのオリジン (末尾の `.` は省略可能) |
| `--mode`, `-m` | 後述する検証ケース |
| `--target-name`, `-t` | 加工対象の名前 (`ds-*`、`nsec-*` モードでは必須)。`www` のような相対名は `--origin` に対して解決され、末尾に `.` がある名前は FQDN として扱われます |
| `--target-type` | 型ビットマップ不整合モードで追加する問い合わせ型 (既定: `A`) |
| `--zsk-private-key` | `nsec-*` モードで変更した NSEC/NSEC3 RRset を再署名する ZSK の `.private` ファイル (RSASHA256 (8)、ECDSAP256SHA256 (13)、ED25519 (15)、ED448 (16))。省略時は `--key-directory` から自動選択 |
| `--key-directory`, `-k` | `ldns-keygen` 形式の KSK/ZSK 鍵ファイルがあるディレクトリ。ゾーンファイル名から `K<zone>.+<algorithm>+<keytag>.key` を探し、DNSKEY フラグ 257 を KSK、256 を ZSK として選択する。対応する秘密鍵は `.key` と同じベース名に `.private` を付けたファイルを使う |
| `--sign-zone` | dnspython でゾーン全体を署名する。`ds-keytag-mismatch` と `ds-hash-mismatch` は加工後に署名し、`ds-rrsig-corrupt`、`dnskey-rrsig-*`、`nsec-*` は署名後に加工する |
| `--increment-serial`, `-s` | SOA レコードの Serial を 1 インクリメントする |

出力先ディレクトリが存在しない場合は作成されます。対象レコードが見つからない場合、ゾーンを出力せずエラー終了します。

## 検証ケース

| `--mode` | 加工するゾーン | 内容 | dnssec-check.jp の対応パターン |
| --- | --- | --- | --- |
| `success` | 親または子 | 変更せず出力 | 成功パターン |
| `ds-keytag-mismatch` | 親 | 委任先 `DS` の Key Tag を1増やす | Key Tag ミスマッチ |
| `ds-hash-mismatch` | 親 | 委任先 `DS` の Digest の末尾 1バイトを反転する | ハッシュ値ミスマッチ |
| `ds-rrsig-corrupt` | 親 | 委任先 `DS` の電子署名データである `RRSIG` の署名値を破損する | DSリソースレコードの検証失敗 |
| `dnskey-rrsig-corrupt` | 子 | ゾーンの頂点の `DNSKEY` の電子署名データである `RRSIG` の署名値を破損する | DNSKEYリソースレコードの検証失敗 |
| `dnskey-rrsig-expired` | 子 | ゾーンの頂点の `DNSKEY` の電子署名データである `RRSIG` の有効期限を `2010-01-01T00:00:00Z` にする | DNSKEYリソースレコードの検証失敗（有効期限切れ） |
| `nsec-cover-mismatch` | 子 | 指定名を覆う NSEC の Next Domain Name を所有者名にして、指定名をカバーしない状態にする | 不在証明のカバー不成立 |
| `nsec3-cover-mismatch` | 子 | 指定名を覆う NSEC3 の Next Hashed Owner Name を所有者ハッシュにして、指定名をカバーしない状態にする | 不在証明のカバー不成立 |
| `nsec3-optout-cover-mismatch` | 子 | 指定名を覆う Opt-Out フラグ付き NSEC3 だけを対象に、カバー範囲を壊す | Opt-Out 不在証明のカバー不成立 |
| `nsec-type-bitmap-mismatch` | 子 | 指定名の NSEC 型ビットマップに問い合わせ型を追加する | NODATA 不在証明の不整合 |
| `nsec3-type-bitmap-mismatch` | 子 | 指定名の NSEC3 型ビットマップに問い合わせ型を追加する | NODATA 不在証明の不整合 |

加工対象となる `DS` は親ゾーンのものであり、加工対象となる `RRSIG` は子ゾーンのものです。同じ委任先について複数の失敗パターンを公開する場合は、毎回、元の正常な署名済みゾーンから個別に出力してください。

`nsec-*` モードを署名済みゾーンに対して実行する場合は、NSEC/NSEC3 の RDATA を変更した後、`--zsk-private-key` で指定した ZSK、または `--key-directory` から自動選択した ZSK を使って変更対象 RRset の RRSIG だけを再生成します。`--sign-zone` を指定した場合は、未署名ゾーンに NSEC/NSEC3 を生成してからゾーン全体を署名し、その後に NSEC/NSEC3 を壊して変更対象 RRset の RRSIG だけを再生成します。`--key-directory` を使う場合は、`ldns-keygen` で生成した対応アルゴリズム（RSASHA256、ECDSAP256SHA256、ED25519、ED448）の `.key` と、同じベース名の `.private` を同じディレクトリに配置してください。

`*-cover-mismatch` は、存在しない名前に対する NXDOMAIN 応答のカバー範囲を壊します。AAAA レコードだけが存在する名前への A 問い合わせのような NODATA 応答には、`*-type-bitmap-mismatch` を使います。対象名のビットマップに A を追加すると、権威サーバーの A/NODATA 応答と不在証明が矛盾します。

ワイルドカード応答の次に近い名前の不在証明も、実際に問い合わせる名前を `--target-name` に指定して `*-cover-mismatch` を使います。NSEC3 Opt-Out を使う委任ケースでは、`nsec3-optout-cover-mismatch` を指定してください。このモードは Opt-Out フラグを持つ NSEC3 が対象名を覆う場合だけ変更します。

## 実行例

親ゾーン `example.test.` にある `keytag.ds.error.example.test.` への委任の DS を壊してから署名します。

```bash
.venv/bin/python corrupt_zone.py \
  --input example.test.zone \
  --output example.test.ds-keytag.zone.signed \
  --origin example.test. \
  --mode ds-keytag-mismatch \
  --target-name keytag.ds.error.example.test. \
  --key-directory /path/to/keys \
  --sign-zone
```

同じ親ゾーンで、DS の Digest 不整合と DS の署名破損を作成する例です。DS の署名破損は、署名後に `RRSIG DS` を壊します。

```bash
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-hash.zone.signed -d example.test. -m ds-hash-mismatch -t hash.ds.error.example.test. -k /path/to/keys --sign-zone
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-rrsig.zone.signed -d example.test. -m ds-rrsig-corrupt -t sign.ds.error.example.test. -k /path/to/keys --sign-zone
```

子ゾーン `sign.dnskey.error.example.test.` を署名し、その DNSKEY 署名を壊します。子ゾーンでは `--target-name` は不要です。

```bash
.venv/bin/python corrupt_zone.py \
  --input sign.dnskey.error.example.test.zone \
  --output sign.dnskey.error.example.test.zone.signed \
  --origin sign.dnskey.error.example.test. \
  --mode dnskey-rrsig-corrupt \
  --key-directory /path/to/keys \
  --sign-zone
```

有効期限切れのケースでは `--mode dnskey-rrsig-expired` を指定します。

```bash
.venv/bin/python corrupt_zone.py -i expire.dnskey.error.example.test.zone -o expire.dnskey.error.example.test.zone.signed -d expire.dnskey.error.example.test. -m dnskey-rrsig-expired -k /path/to/keys --sign-zone
```

存在しない `missing.error.example.test.` を覆う NSEC のカバー範囲を、署名後に壊して対象 NSEC RRset だけ再署名する例です。

```bash
.venv/bin/python corrupt_zone.py \
  --input error.example.test.zone \
  --output error.example.test.nsec-cover.zone.signed \
  --origin error.example.test. \
  --mode nsec-cover-mismatch \
  --target-name missing.error.example.test. \
  --key-directory /path/to/keys \
  --sign-zone
```

NSEC3 署名済みゾーンを対象にする場合は、同じ対象名に `--mode nsec3-cover-mismatch` を指定します。`--sign-zone` を指定すると、NSEC3 レコードを生成してから署名し、その後にカバー範囲を壊します。

Opt-Out NSEC3 のカバー範囲を壊す場合は、`--mode nsec3-optout-cover-mismatch` を指定します。対象名は、変更対象となる Opt-Out NSEC3 が実際に覆う名前にしてください。

AAAA レコードだけを持つ `optout-cover-mismatch.nsec3.error.example.test.` の A/NODATA 不在証明を壊すには、次のように実行します。

```bash
.venv/bin/python corrupt_zone.py \
  --input optout-cover-mismatch.nsec3.error.example.test.zone \
  --output optout-cover-mismatch.nsec3.error.example.test.nsec3-bitmap.zone.signed \
  --origin nsec3.error.example.test. \
  --mode nsec3-type-bitmap-mismatch \
  --target-name optout-cover-mismatch.nsec3.error.example.test. \
  --target-type A \
  --key-directory /path/to/keys \
  --sign-zone
```

通常の NSEC ゾーンでは `--mode nsec-type-bitmap-mismatch` を指定します。`--target-type` は省略時に `A` となるため、上の例では省略可能です。

## テスト

NSEC/NSEC3 のカバー範囲、NODATA 型ビットマップ、NSEC3 Opt-Out の加工は、次のコマンドで検証できます。

```bash
.venv/bin/python -m unittest -v test_corrupt_zone.py
```

## NSD への反映

各出力ファイルを NSD の `zonefile:` に指定し、変更後は `nsd-checkconf` で設定とゾーンを確認し、NSD を再読み込みします。実際のコマンドは NSD の導入方法・権限設定に合わせてください。

```text
zone:
    name: "sign.dnskey.error.example.test."
    zonefile: "sign.dnskey.error.example.test.zone.signed"
```

※公開環境では、失敗パターン用の委任先を正常系とは別のゾーンとして構成してください。

## 注意事項

- 出力ゾーンは意図的に DNSSEC 検証に失敗します。通常利用している本番ゾーンには使用しないでください。
- `nsec-*` モードでは、変更した NSEC/NSEC3 RRset の RRSIG だけを ZSK で再生成します。それ以外の署名は再計算しません。
- 署名および RRSIG の再生成は RSASHA256 (8)、ECDSAP256SHA256 (13)、ED25519 (15)、ED448 (16) の鍵に対応しています。

## 親ゾーンの更新について

親ゾーンについては、未署名の親ゾーンを入力し、`--sign-zone` と `--key-directory` を指定することで、個別に事象を発生させることができます。`ds-keytag-mismatch` と `ds-hash-mismatch` は DS を変更してから署名し、`ds-rrsig-corrupt` は署名後に `RRSIG DS` を壊します。

`-o` で指定したファイルが、その実行結果のゾーンファイルです。複数のドメイン名を同じ親ゾーンで壊す場合は、最初の実行で署名と1件目の加工を行い、その出力を次の実行の `-i` に指定します。2件目以降は、すでに署名済みのゾーンを再署名せずに加工を重ねるため、`--sign-zone` を指定しません。最後の実行で指定した `-o` のファイルを NSD の `zonefile:` に設定してください。途中のファイルは作業用なので、不要になれば削除できます。

```bash
# 1件目: 未署名の元ファイルから署名して加工
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.zone.work1 -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test. -k /path/to/keys --sign-zone

# 2件目: 1件目の出力に加工を重ねる
.venv/bin/python corrupt_zone.py -i example.test.zone.work1 -o example.test.zone.signed -m ds-hash-mismatch -d example.test. -t hash.ds.error.example.test.
```

この例では、NSD に読み込ませるファイルは最後の `example.test.zone.signed` です。

各検証ケースを独立したゾーンファイルにする場合は、毎回、正常な元ファイルを `-i` に指定し、ケースごとに異なる `-o` を指定してください。その場合は各コマンドに `--sign-zone` を付けます。

1. example.test.zone を編集
1. `.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-keytag.zone.signed -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test. -k /path/to/keys --sign-zone`
1. `.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-hash.zone.signed -m ds-hash-mismatch -d example.test. -t hash.ds.error.example.test. -k /path/to/keys --sign-zone`
1. `.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-rrsig.zone.signed -m ds-rrsig-corrupt -d example.test. -t sign.ds.error.example.test. -k /path/to/keys --sign-zone`
1. 権威サーバーでゾーンファイルを再読み込み
