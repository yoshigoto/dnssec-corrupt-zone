# dnssec-corrupt-zone

DNSSEC ゾーンファイルを検証用に加工する Python スクリプトです。親ゾーンの `DS`、子ゾーンの `DNSKEY` と否定応答に使われる NSEC/NSEC3 を意図的に不整合にします。[DNSSEC 委任状態検証ツール](https://www.on-link.jp/dnssec-validator/) で、実際に壊れた事例を確認することができます。

このツールは NSD の再読み込みを行いません。`--sign-zone` を指定すると、`ldns-keygen` 形式の鍵ファイルを使って dnspython でゾーン全体を署名します。`RRSIG` を破損するモードと `nsec-*` モードでは、署名後に対象レコードを壊します。`nsec-*` モードでは、指定された ZSK、または `--key-directory` から自動選択した ZSK で変更対象 NSEC/NSEC3 RRset の RRSIG だけを再生成します。必要に応じて署名前、または署名済みのゾーンファイルを用意し、このツールで出力されたゾーンファイルを NSD で読み込ませてください。

なお、本ツールで作成したドメイン名のリストを、[DNSSEC 信頼の連鎖確認ページ](https://www.dnssec-check.jp/) で公開しています。

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
.venv/bin/python corrupt_zone.py --input INPUT --output OUTPUT --origin ZONE_ORIGIN --mode MODE [--target-name NAME] [--target-type TYPE] [--zsk-private-key PRIVATE_FILE] [--key-directory KEY_DIR] [--sign-zone]
```

| 引数 | 説明 |
| --- | --- |
| `--input`, `-i` | 加工対象となるゾーンファイル |
| `--output`, `-o` | NSD に読み込ませる加工後のゾーンファイル |
| `--origin`, `-d` | 入力ゾーンのオリジン (末尾の `.` は省略可能) |
| `--mode`, `-m` | 後述する検証ケース |
| `--target-name`, `-t` | 加工対象の名前 (`ds-*`、`nsec-*`、`a-rrsig-corrupt` モードでは必須)。`www` のような相対名は `--origin` に対して解決され、末尾に `.` がある名前は FQDN として扱われます |
| `--target-type` | 型ビットマップ不整合モードで追加する問い合わせ型 (既定: `A`) |
| `--zsk-private-key` | `nsec-*` モードで変更した NSEC/NSEC3 RRset を再署名する ZSK の `.private` ファイル (RSASHA256 (8)、ECDSAP256SHA256 (13)、ED25519 (15)、ED448 (16))。省略時は `--key-directory` から自動選択 |
| `--key-directory`, `-k` | `ldns-keygen` 形式の KSK/ZSK 鍵ファイルがあるディレクトリ。ゾーンファイル名から `K<zone>.+<algorithm>+<keytag>.key` を探し、DNSKEY フラグ 257 を KSK、256 を ZSK として選択する。対応する秘密鍵は `.key` と同じベース名に `.private` を付けたファイルを使う |
| `--sign-zone` | dnspython でゾーン全体を署名する。`ds-keytag-mismatch` と `ds-hash-mismatch` は加工後に署名し、`ds-rrsig-corrupt`、`dnskey-rrsig-*`、`nsec-*` は署名後に加工する |
| `--sign-only` | `--sign-zone` と署名後加工モードを併用し、署名のみ行う。補助スクリプトが署名済みファイルを保存してから別工程で加工する場合に使う |
| `--nsec3-iterations` | `nsec3-* --sign-zone` の署名時に使う NSEC3 反復回数 (0〜65535)。省略時は既存の `NSEC3PARAM`、なければ 0 |
| `--nsec3-salt` | `nsec3-* --sign-zone` の署名時に使う偶数桁の16進 salt (最大255バイト)。省略時は既存の `NSEC3PARAM`、なければ salt なし。salt なしを明示する場合は空文字列を指定 |

出力先ディレクトリが存在しない場合は作成されます。対象レコードが見つからない場合、ゾーンを出力せずエラー終了します。

SOA の Serial は入力値を保持し、このツールでは変更しません。AXFR/IXFR などによる配布で Serial の更新が必要な場合は、署名前のテンプレートやゾーン更新処理で更新し、その後に署名・検証用の加工を行ってください。

## 検証ケース

以下の「検証への影響」は、加工されたゾーンに対する DNSSEC 検証の結果です。NSEC/NSEC3 の不在証明ケースでは、署名値は正しいまま証明内容を不整合にし、署名の検証失敗とは区別できるようにしています。

| `--mode` | ゾーン | 壊し方 | 検証への影響 | dnssec-check.jp の表示 |
| --- | --- | --- | --- | --- |
| `success` | 親または子 | レコードを変更しない | 他の不整合がなければ検証成功 | 成功パターン |
| `ds-keytag-mismatch` | 親 | 委任先 `DS` の Key Tag を1増やす | `DS` が子の `DNSKEY` に一致せず、信頼の連鎖を確立できない | Key Tag ミスマッチ |
| `ds-hash-mismatch` | 親 | 委任先 `DS` の Digest の末尾1バイトを反転する | `DS` が子の `DNSKEY` に一致せず、信頼の連鎖を確立できない | ハッシュ値ミスマッチ |
| `ds-rrsig-corrupt` | 親 | `DS` を覆う `RRSIG` の署名値の末尾1バイトを反転する | 親ゾーンの `DS` RRset の署名検証に失敗する | DS リソースレコードの検証失敗 |
| `dnskey-rrsig-corrupt` | 子 | ゾーン頂点の `DNSKEY` を覆う `RRSIG` の署名値の末尾1バイトを反転する | 子ゾーンの `DNSKEY` RRset の署名検証に失敗し、子の鍵を認証できない | DNSKEY リソースレコードの検証失敗 |
| `dnskey-rrsig-expired` | 子 | ゾーン頂点の `DNSKEY` を覆う `RRSIG` の有効期限を `2010-01-01T00:00:00Z` にする | `DNSKEY` RRset の署名が期限切れとして拒否される | DNSKEY リソースレコードの検証失敗（有効期限切れ） |
| `a-rrsig-corrupt` | 子 | 指定名の `A` を覆う `RRSIG` の署名値の末尾1バイトを反転する | 対象名の `A` RRset の署名検証に失敗する | A リソースレコードの検証失敗 |
| `nsec-cover-mismatch` | 子 | 不在名を覆う NSEC の Next Domain Name をその不在名にする | 終端名は範囲に含まれないため、NXDOMAIN 等の不在証明が成立しない | 不在証明のカバー不成立 |
| `nsec3-cover-mismatch` | 子 | 不在名を覆う NSEC3 の Next Hashed Owner Name をその不在名のハッシュにする | NXDOMAIN 等に必要な NSEC3 の不在証明が成立しない | 不在証明のカバー不成立 |
| `nsec3-optout-cover-mismatch` | 子 | 対象名を覆う Opt-Out フラグ付き NSEC3 の Next を対象名のハッシュにする | DS のない委任について、DS 不在を示す Opt-Out 証明が成立しない | Opt-Out 不在証明のカバー不成立 |
| `nsec-type-bitmap-mismatch` | 子 | 対象名の NSEC 型ビットマップに、存在しない問い合わせ型を追加する | 権威応答は NODATA なのにビットマップは型の存在を示すため、NODATA 証明が不整合になる | NODATA 不在証明の不整合 |
| `nsec3-type-bitmap-mismatch` | 子 | 対象名の NSEC3 型ビットマップに、存在しない問い合わせ型を追加する | 権威応答は NODATA なのにビットマップは型の存在を示すため、NODATA 証明が不整合になる | NODATA 不在証明の不整合 |

型ビットマップの既定の問い合わせ型は `A` です。例えば `AAAA` だけを持つ名前に対する A/NODATA を試す場合は、`--target-type A` を指定します。NXDOMAIN やワイルドカード応答の次に近い名前の不在証明を試す場合は、実際に問い合わせる名前を `--target-name` に指定して `*-cover-mismatch` を使います。

加工対象となる `DS` は親ゾーンのものであり、加工対象となる `RRSIG` は子ゾーンのものです。同じ委任先について複数の失敗パターンを公開する場合は、毎回、加工前の正常なゾーンから始め、モードに応じた署名状態（DS 値の加工は署名前、`RRSIG` の加工は署名後）で処理してください。

`nsec-*` モードを署名済みゾーンに対して実行する場合は、NSEC/NSEC3 の RDATA を変更した後、`--zsk-private-key` で指定した ZSK、または `--key-directory` から自動選択した ZSK を使って変更対象 RRset の RRSIG だけを再生成します。`--sign-zone` を指定した場合は、未署名ゾーンに NSEC/NSEC3 を生成してからゾーン全体を署名し、その後に NSEC/NSEC3 を壊して変更対象 RRset の RRSIG だけを再生成します。`--key-directory` を使う場合は、`ldns-keygen` で生成した対応アルゴリズム（RSASHA256、ECDSAP256SHA256、ED25519、ED448）の `.key` と、同じベース名の `.private` を同じディレクトリに配置してください。

`nsec3-* --sign-zone` は、dnspython の RRset 署名機能を使って NSEC3 専用の署名済みゾーンを作り、NSEC は生成しません。DNSKEY と NSEC3PARAM を用意し、署名対象の RRset に付く `RRSIG` も型ビットマップに含めて NSEC3 チェーンを生成してから署名します。empty non-terminal（配下の名前は存在するが、その名前自身にはレコードがない名前）も NSEC3 の対象に含め、委任先の glue や委任配下のデータは署名・ハッシュ化しません。委任の NS 自体は署名せず、DS がある場合だけ DS を署名します。

NSEC3PARAM がなければ、SHA-1、反復回数 0、salt なしを使用します。既存の NSEC3PARAM が 1 レコードあれば、そのアルゴリズム・反復回数・salt を使います。`--nsec3-iterations` と `--nsec3-salt` を指定すると、それぞれ既存値に優先して署名時の値を設定できます。`ldns-signzone -n` を使っていた従来の版は、指定しない場合の反復回数が 1 でしたが、現在は 0 です。従来と同じ結果にするには `--nsec3-iterations 1` を指定してください。再署名時は古い NSEC/NSEC3 と RRSIG を取り除いて証明チェーンを作り直します。`nsec3-optout-cover-mismatch --sign-zone` では DS のない委任のハッシュを省略し、Opt-Out フラグ付きの範囲を生成します。

`nsec-cover-mismatch` と `nsec3-cover-mismatch` は、存在しない名前に対する NXDOMAIN 応答などで必要なカバー範囲を壊します。カバー範囲の終端は範囲に含まれないため、Next を指定名（NSEC3 では指定名のハッシュ）に変更します。Next を所有者自身にすると循環範囲が広がり、不在証明が検証成功する場合があるため、自己ループは使いません。変更対象 RRset の署名は再生成します。`nsec3-optout-cover-mismatch` は、Opt-Out フラグを持つ NSEC3 が対象名を覆う場合に限り、その DS 不在証明を壊します。

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

例えば未署名の入力ゾーンに `unsigned IN NS ns.example.test.`（DS なし）がある場合、Python 単体でも次のように署名・加工できます。`ldns-signzone` は不要です。

```bash
.venv/bin/python corrupt_zone.py \
  --input optout.example.test.zone \
  --output optout.example.test.zone.signed \
  --origin optout.example.test. \
  --mode nsec3-optout-cover-mismatch \
  --target-name unsigned \
  --key-directory /path/to/keys \
  --sign-zone
```

Opt-Out の未署名委任とは別に、AAAA レコードだけを持つ `aaaa.nsec3.error.example.test.` の A/NODATA 不在証明を壊すには、次のように実行します。

```bash
.venv/bin/python corrupt_zone.py \
  --input nsec3.error.example.test.zone \
  --output nsec3.error.example.test.nsec3-bitmap.zone.signed \
  --origin nsec3.error.example.test. \
  --mode nsec3-type-bitmap-mismatch \
  --target-name aaaa.nsec3.error.example.test. \
  --target-type A \
  --key-directory /path/to/keys \
  --sign-zone
```

通常の NSEC ゾーンでは `--mode nsec-type-bitmap-mismatch` を指定します。`--target-type` は省略時に `A` となるため、上の例では省略可能です。

## 親ゾーンの DS を加工する場合

一括生成スクリプトは、親ゾーンテンプレートから作った未署名ゾーンに DS を追加し、`ds-keytag-mismatch` と `ds-hash-mismatch` を適用してから親ゾーンを署名します。その後、署名済みゾーンに `ds-rrsig-corrupt` を適用します。通常はこのスクリプトに任せられるため、手作業での更新が必要な場合だけ以下の順序を使ってください。

独自の署名手順を使う場合、Key Tag／Digest の加工は未署名ファイルに適用し、その後に親ゾーンを署名します。`ds-rrsig-corrupt` は署名済みファイルに適用してください。この加工後に再署名すると破損した署名が修復されます。

```bash
# 未署名ゾーンの DS を加工（必要な加工をすべて行ってから署名）
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.zone.work1 -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test.
.venv/bin/python corrupt_zone.py -i example.test.zone.work1 -o example.test.zone.work2 -m ds-hash-mismatch -d example.test. -t hash.ds.error.example.test.

# example.test.zone.work2 を署名し、出力を example.test.zone.signed とした場合
.venv/bin/python corrupt_zone.py -i example.test.zone.signed -o example.test.zone.final -m ds-rrsig-corrupt -d example.test. -t sign.ds.error.example.test.
```

各検証ケースを独立したゾーンファイルにする場合は、ケースごとに正常な未署名ゾーンから始めます。加工後に署名するのは Key Tag／Digest のケースで、`ds-rrsig-corrupt` は署名後の最後に適用します。NSD に読み込ませるのは加工がすべて終わったファイルです。

複数の検証ケースをまとめて作成する場合や、親ゾーンの DS 追加から署名・加工まで一連の処理を任せる場合は、次の「補助スクリプト」にある一括生成スクリプトを利用できます。

## 補助スクリプト

`scripts/` にはゾーン生成・署名・加工をまとめて実行する POSIX `sh` スクリプトと、処理を担う Python スクリプトがあります。通常は一括生成スクリプトを使い、既存の署名手順を使う場合や特定工程だけを実行する場合は表の個別スクリプトを使ってください。

| スクリプト | 用途・入出力 |
| --- | --- |
| [`dnssec_generate_error_zones.sh`](scripts/dnssec_generate_error_zones.sh) | 一括実行。テンプレートからゾーンを生成し、子ゾーン署名・加工、親ゾーンへの DS 追加・加工・署名、NSEC/NSEC3 ケース作成まで行う。`--key-dir`、`--template-dir`、`--output-dir` で各ディレクトリを指定する |
| [`dnssec_make_error_zonefiles.sh`](scripts/dnssec_make_error_zonefiles.sh) | テンプレートから親・子の未署名ゾーンファイルだけを生成する。署名や DS 追加はしない。`--template-dir`、`--output-dir` を指定できる |
| [`dnssec_sign_child_zones.sh`](scripts/dnssec_sign_child_zones.sh) | 指定したベースゾーン名に一致する子ゾーンファイルを一括署名し、各入力に `.signed` を付けたファイルを作る。テンプレートは署名対象外 |
| [`dnssec_sign_zone.sh`](scripts/dnssec_sign_zone.sh) | 1つのゾーンファイルを `corrupt_zone.py` で署名し、入力ファイル名に `.signed` を付けて出力する |
| [`dnssec_corrupt_child_zone.sh`](scripts/dnssec_corrupt_child_zone.sh) | 対応する子ゾーンの DNSKEY 署名破損・期限切れ、または A 署名破損のファイルを作成する。テンプレートディレクトリを第2引数に指定できる |
| [`dnssec_corrupt_parent_zone.sh`](scripts/dnssec_corrupt_parent_zone.sh) | 親ゾーンファイルを指定モード（`ds-keytag-mismatch`、`ds-hash-mismatch`、`ds-rrsig-corrupt`）で加工し、入力ファイルを更新する |
| [`dnssec_nsec_corrupt_zone.sh`](scripts/dnssec_nsec_corrupt_zone.sh) | NSEC/NSEC3 ケースを署名・加工する。型ビットマップ用に `--target-type`、NSEC3 用に `--nsec3-iterations`、`--nsec3-salt` を指定できる (省略時の反復回数は 0)。既存の `.signed` は `.signed.orig` に退避される |
| [`dnssec_add_ds_records.py`](scripts/dnssec_add_ds_records.py) | 親ゾーン内の NS 委任を確認し、鍵ディレクトリの `.ds` ファイルから DS を追加する。親ゾーンファイルを直接更新する |

作業ディレクトリは任意で、例えば一括生成は次のように実行できます。

```sh
PYTHON=.venv/bin/python \
  sh /path/to/dnssec-corrupt-zone/scripts/dnssec_generate_error_zones.sh \
  example.test.zone --key-dir /path/to/keys --output-dir /path/to/output
```

テンプレートは既定でリポジトリの `templates/` から読み込みます。別の場所を使う場合は `--template-dir DIR`、生成先を指定する場合は `--output-dir DIR` を指定します。どちらも相対パスはコマンド実行時のカレントディレクトリを基準に解決します。出力先は未作成でも作成されます。`dnssec_make_error_zonefiles.sh` 単体にも、同じ `--template-dir` / `--output-dir` オプションを指定できます。

独自のテンプレートディレクトリには、`template.<base-zone>.zone`（親）、`template.algorithm.<base-zone>.zone`（通常の子）、`template.optout.algorithm.<base-zone>.zone`（Opt-Out 用の子）を用意してください。Opt-Out 用テンプレートには、`unsigned` という名前の NS 委任を置き、DS は置きません。

`PYTHON` は Python 実行ファイル、`--key-dir DIR` は鍵ディレクトリを指定します。鍵ディレクトリは環境変数 `DNSSEC_KEY_DIR` でも指定でき、`--key-dir` が優先されます。どちらも未指定の場合は、実行時のカレントディレクトリから見た `../keys` です。Python の既定値は `python3` です。スクリプト本体と `corrupt_zone.py` はスクリプトの配置場所を基準に検索します。個別の署名スクリプトでは `DNSSEC_ZONE_DIR` でゾーンディレクトリも指定できます。署名処理は dnspython と cryptography で行います。

`dnssec_make_error_zonefiles.sh` は NSEC と NSEC3 の型ビットマップ不整合について、A に加えて MX と TXT の問い合わせ型を使うゾーンファイルも生成します。NSEC3 のカバー不成立、型ビットマップ不整合、Opt-Out カバー不成立には、次の4つのパラメーター組み合わせを持つゾーンも生成します。

| ゾーン名の追加部分 | NSEC3 反復回数 | NSEC3 salt |
| --- | ---: | --- |
| `iter0.nosalt` | 0 | なし |
| `iter0.saltA1B2` | 0 | `A1B2` |
| `iter1.nosalt` | 1 | なし |
| `iter1.saltA1B2` | 1 | `A1B2` |

例えば `cover.mismatch.nsec3.iter1.saltA1B2.rsasha256.<zone>.zone` は、反復回数 1、salt `A1B2` の NSEC3 ゾーンにカバー不成立を作ります。`iter1.nosalt` は反復回数 1、salt なしの設定です。`dnssec_generate_error_zones.sh` で署名・DS 追加まで行う場合、追加された委任先それぞれについても、通常と同じ形式の `.key`、`.private`、`.ds` ファイルが鍵ディレクトリに必要です。単に未署名のゾーンファイルを作る場合は `dnssec_make_error_zonefiles.sh` を使ってください。

`dnssec_nsec_corrupt_zone.sh` では、`--target-type TYPE` でビットマップに追加する型を、`--nsec3-iterations COUNT` と `--nsec3-salt HEX` で NSEC3 の署名パラメーターを指定できます。salt は偶数桁の16進数です。例えば次の指定は反復回数 1、salt `A1B2` の NSEC3 ゾーンを作ります。

```sh
sh scripts/dnssec_nsec_corrupt_zone.sh \
  cover.mismatch.nsec3.iter1.saltA1B2.rsasha256.example.test.zone \
  nsec3-cover-mismatch cover.mismatch.nsec3.iter1.saltA1B2.rsasha256.example.test \
  /path/to/keys . \
  --nsec3-iterations 1 --nsec3-salt A1B2
```

ゾーン生成スクリプトは、親ゾーンテンプレートをコピーした後、親ゾーンの各子ゾーン委任に対応する `K<child-zone>.+*.ds` ファイルを、`--key-dir` または `DNSSEC_KEY_DIR` で選択した鍵ディレクトリから探し、DS レコードを追加します。DS ファイルは `ldns-key2ds` のゾーン形式出力を保存したもの（例: `ldns-key2ds Kchild.example.+008+12345.key > Kchild.example.+008+12345.ds`）を使います。委任先の DS ファイルがない、内容が DS レコードでない、または owner 名が委任先と異なる場合はエラー終了します。鍵ロールオーバーで複数の DS ファイルがある場合はすべて追加し、既に同じ DS がある場合は重複させません。親ゾーンにある既存 DS が DS ファイル群に含まれない場合もエラーになります。

子ゾーンの origin は、各子ゾーンのファイル名から末尾の `.zone` を除いたドメイン名です。例えば `sign.dnskey.error.ed25519.example.test.zone` は `sign.dnskey.error.ed25519.example.test` として署名・加工し、この子ドメインの鍵を使用します。ベースゾーン名 `example.test` を使うのは親ゾーンの処理だけです。

補助スクリプトの引数と鍵選択は、次の回帰テストで確認できます。このテストは外部コマンドをスタブに置き換え、実際の暗号署名は行いません。

```sh
python3 -m unittest -v test_shell_scripts.py
```

`ldns-keygen` がある場合は、それで作った実鍵を使って Opt-Out ゾーンを署名・加工し、対象のハッシュが省略されていること、変更した NSEC3 とその RRSIG 以外が維持されることも検証します。コマンドがない場合、その実鍵テストだけスキップします。

## テスト

NSEC/NSEC3 のカバー範囲、NODATA 型ビットマップ、NSEC3 Opt-Out の加工は、次のコマンドで検証できます。

```bash
.venv/bin/python -m unittest -v test_corrupt_zone.py
```

テストでは、正常な NSEC3 ゾーンの循環チェーン、型ビットマップ、empty non-terminal、委任・glue の扱いと署名を確認してから、加工後も全署名が有効で、指定した NSEC3 RRset だけが変更されることを確認します。署名は対応する 4 アルゴリズムで検証します。`ldns-verify-zone` がある場合は、正常系のゾーン構造を独立した実装でも確認します。

### Opt-Out ケースの仕組みと比較方法

生成するゾーンの構造は次のとおりです。

```text
dnssec-check.jp.
  └─ optout.mismatch.nsec3.rsasha256.dnssec-check.jp.  ← DS のある署名済みゾーン
       └─ unsigned                                     ← NS だけの未署名委任、DS なし
```

未署名委任 `unsigned` は存在しますが、Opt-Out ではその名前に一致する NSEC3 を省略できます。その代わり、`unsigned` のハッシュを覆う NSEC3 に Opt-Out フラグを立てます。これにより、バリデータは「この範囲には DS のない未署名委任があり得る」と判断でき、`unsigned` への DS 問い合わせの不在証明を検証できます。通常の存在しない名前に対する NXDOMAIN や、AAAA だけの名前への A/NODATA とは異なるケースです。

`nsec3-optout-cover-mismatch --sign-zone` は Python で Opt-Out NSEC3 チェーンを生成し、DS のない委任のハッシュを省略します。委任の NS や glue は署名しません。`dnssec_nsec_corrupt_zone.sh` は `--sign-only` で有効な署名済みファイルを保存した後、対象 NSEC3 とその RRSIG だけを加工・再署名します。

続いて `nsec3-optout-cover-mismatch` が、`unsigned` を覆う Opt-Out NSEC3 の Next を `unsigned` 自身のハッシュに変更し、その NSEC3 RRset だけを再署名します。範囲の終端はカバー対象に含まれないため、DS 不在証明が成立しなくなります。署名そのものの検証失敗ではありません。

単独で試す場合は、リポジトリ直下から次のように実行できます。公開ゾーンや既存の鍵は変更せず、一時ディレクトリに学習用の鍵とゾーンを作ります。

```sh
zone=optout.mismatch.nsec3.rsasha256.dnssec-check.jp
workdir=$(mktemp -d)
sh scripts/dnssec_make_error_zonefiles.sh --output-dir "$workdir"
(
  mkdir "$workdir/keys"
  cd "$workdir/keys"
  ldns-keygen -a RSASHA256 -b 2048 -k "$zone"
  ldns-keygen -a RSASHA256 -b 2048 "$zone"
)
PYTHON=.venv/bin/python sh scripts/dnssec_nsec_corrupt_zone.sh \
  "$zone.zone" nsec3-optout-cover-mismatch "$zone" \
  "$workdir/keys" "$workdir"

diff -u "$workdir/$zone.zone.signed.orig" "$workdir/$zone.zone.signed"
```

- `.zone`：未署名委任を含む入力ゾーン。
- `.zone.signed.orig`：正常な Opt-Out 署名済みゾーン。
- `.zone.signed`：DS 不在証明を加工したゾーン。

差分では、NSEC3 の Next と対応する `RRSIG NSEC3` の署名値だけが変わります（書式・並び順も変わる場合があります）。ハッシュアルゴリズム、Opt-Out フラグ、反復回数、salt、型ビットマップは変えません。`diff` は差分があると終了コード 1 を返します。

権威サーバーで比較する場合、両ファイルを同じゾーン名で順番に読み込ませ、`unsigned.optout.mismatch.nsec3.rsasha256.dnssec-check.jp. DS` を問い合わせます。親ゾーンの KSK を信頼アンカーとして設定したバリデータで、正常系の DS 不在証明は検証成功し、加工後は不在証明の不足で検証失敗することを確認してください。NSD は権威応答を返すだけなので、`dig +dnssec` でレコードを見たことだけでは検証成功・失敗の確認になりません。

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
