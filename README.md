# dnssec-corrupt-zone

DNSSEC ゾーンファイルを検証用に加工する Python スクリプトです。親ゾーンの `DS` や、子ゾーンの `DNSKEY`、否定応答に使う NSEC/NSEC3 を意図的に不整合にします。加工したゾーンは、[DNSSEC 委任状態検証ツール](https://www.on-link.jp/dnssec-validator/)で検証できます。

このツールは NSD を再読み込みしません。`--sign-zone` を指定すると、ldns 互換形式の鍵ファイルを使って dnspython でゾーンに署名します。署名後に加工するモードでは、対象レコードを変更します。`nsec-*` モードでは、変更した NSEC/NSEC3 RRset の RRSIG だけを、指定した ZSK または `--key-directory` から選んだ ZSK で再生成します。出力したゾーンファイルを NSD に読み込ませてください。

本ツールで作成したドメイン名の一覧は、[DNSSEC 信頼の連鎖確認ページ](https://www.dnssec-check.jp/)で公開しています。

## 必要環境

- Python 3.11 以降
- `dnspython` 2.9 以降、3 未満
- `cryptography` 47 以降
- 親ゾーンと子ゾーンのファイル（用途に応じて署名済み、または未署名）
- 任意: `ldns-keygen`（実鍵を使う一部のテスト）、`ldns-verify-zone`（独立したゾーン検証）

依存パッケージは次のようにインストールできます。

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
.venv/bin/python corrupt_zone.py --input INPUT --output OUTPUT --origin ZONE_ORIGIN --mode MODE [--target-name NAME] [--target-type TYPE] [--zsk-private-key PRIVATE_FILE] [--key-directory KEY_DIR] [--sign-zone] [--sign-only] [--nsec3-iterations COUNT] [--nsec3-salt HEX]
```

| 引数 | 説明 |
| --- | --- |
| `--input`, `-i` | 加工対象となるゾーンファイル |
| `--output`, `-o` | NSD に読み込ませる加工後のゾーンファイル |
| `--origin`, `-d` | 入力ゾーンのオリジン (末尾の `.` は省略可能) |
| `--mode`, `-m` | 後述する検証ケース |
| `--target-name`, `-t` | 加工対象の名前（`ds-*`、`nsec-*`、`a-rrsig-corrupt` では必須）。`www` のような相対名は `--origin` を基準に解決し、末尾に `.` がある名前は絶対名として扱います |
| `--target-type` | 型ビットマップ不整合モードで追加する問い合わせ型（既定値: `A`） |
| `--zsk-private-key` | `nsec-*` モードで変更した NSEC/NSEC3 RRset を再署名する ZSK の `.private` ファイル。対応アルゴリズムは RSASHA256 (8)、ECDSAP256SHA256 (13)、ED25519 (15)、ED448 (16)、MLDSA44 (18) です。省略時は `--key-directory` から自動選択します |
| `--key-directory`, `-k` | ldns 互換形式の KSK/ZSK 鍵ファイルがあるディレクトリ。入力ファイル名から末尾の `.signed`、次に `.zone` を除いた名前を `<zone>` として `K<zone>.+<algorithm>+<keytag>.key` を探し、DNSKEY フラグ 257 を KSK、256 を ZSK として選びます。秘密鍵には同じベース名の `.private` ファイルを使います |
| `--sign-zone` | dnspython でゾーンに署名します。`ds-keytag-mismatch` と `ds-hash-mismatch` は署名前に加工し、`ds-rrsig-corrupt`、`dnskey-rrsig-*`、`nsec-*` は署名後に加工します |
| `--sign-only` | `--sign-zone` と署名後加工モードを併用し、署名だけを行います。署名済みファイルを保存し、別工程で加工する場合に使います |
| `--nsec3-iterations` | `nsec3-* --sign-zone` で使う NSEC3 反復回数（0〜65535）。省略時は既存の `NSEC3PARAM` の値を使い、なければ 0 にします |
| `--nsec3-salt` | `nsec3-* --sign-zone` で使う偶数桁の16進 salt（最大255バイト）。省略時は既存の `NSEC3PARAM` の値を使い、なければ salt なしにします。salt なしを明示する場合は空文字列を指定します |

出力先ディレクトリは、存在しない場合に作成します。対象レコードが見つからない場合はエラー終了し、新しい出力ファイルは作成しません。

SOA の Serial は入力値を保持し、このツールでは変更しません。AXFR/IXFR などで Serial の更新が必要な場合は、署名前にテンプレートまたはゾーン更新処理で変更してください。

## 検証ケース

「検証への影響」は、加工後のゾーンを DNSSEC 検証した結果です。NSEC/NSEC3 の不在証明ケースでは署名を有効なまま保ち、証明内容の不整合と署名検証の失敗を区別します。

| `--mode` | ゾーン | 壊し方 | 検証への影響 | dnssec-check.jp の表示 |
| --- | --- | --- | --- | --- |
| `success` | 親または子 | レコードを変更しない | 他の不整合がなければ検証成功 | 成功パターン |
| `ds-keytag-mismatch` | 親 | 委任先 `DS` の Key Tag を 1 増やす（65535 の次は 0） | `DS` が子の `DNSKEY` に一致せず、信頼の連鎖を確立できない | Key Tag ミスマッチ |
| `ds-hash-mismatch` | 親 | 委任先 `DS` の Digest の末尾バイトの最下位ビットを反転する | `DS` が子の `DNSKEY` に一致せず、信頼の連鎖を確立できない | ハッシュ値ミスマッチ |
| `ds-rrsig-corrupt` | 親 | `DS` を覆う `RRSIG` の署名値の末尾バイトの最下位ビットを反転する | 親ゾーンの `DS` RRset の署名検証に失敗する | DS リソースレコードの検証失敗 |
| `dnskey-rrsig-corrupt` | 子 | ゾーン頂点の `DNSKEY` を覆う `RRSIG` の署名値の末尾バイトの最下位ビットを反転する | 子ゾーンの `DNSKEY` RRset の署名検証に失敗し、子の鍵を認証できない | DNSKEY リソースレコードの検証失敗 |
| `dnskey-rrsig-expired` | 子 | ゾーン頂点の `DNSKEY` を覆う `RRSIG` の有効期限を `2010-01-01T00:00:00Z` にする | `DNSKEY` RRset の署名が期限切れとして拒否される | DNSKEY リソースレコードの検証失敗（有効期限切れ） |
| `a-rrsig-corrupt` | 子 | 指定名の `A` を覆う `RRSIG` の署名値の末尾バイトの最下位ビットを反転する | 対象名の `A` RRset の署名検証に失敗する | A リソースレコードの検証失敗 |
| `nsec-cover-mismatch` | 子 | 不在名を覆う NSEC の Next Domain Name をその不在名にする | 終端名は範囲に含まれないため、NXDOMAIN 等の不在証明が成立しない | 不在証明のカバー不成立 |
| `nsec3-cover-mismatch` | 子 | 不在名を覆う NSEC3 の Next Hashed Owner Name をその不在名のハッシュにする | NXDOMAIN 等に必要な NSEC3 の不在証明が成立しない | 不在証明のカバー不成立 |
| `nsec3-optout-cover-mismatch` | 子 | 対象名を覆う Opt-Out フラグ付き NSEC3 の Next を対象名のハッシュにする | DS のない委任について、DS 不在を示す Opt-Out 証明が成立しない | Opt-Out 不在証明のカバー不成立 |
| `nsec-type-bitmap-mismatch` | 子 | 対象名の NSEC 型ビットマップに、存在しない問い合わせ型を追加する | 権威応答は NODATA なのにビットマップは型の存在を示すため、NODATA 証明が不整合になる | NODATA 不在証明の不整合 |
| `nsec3-type-bitmap-mismatch` | 子 | 対象名の NSEC3 型ビットマップに、存在しない問い合わせ型を追加する | 権威応答は NODATA なのにビットマップは型の存在を示すため、NODATA 証明が不整合になる | NODATA 不在証明の不整合 |

型ビットマップ不整合モードで追加する問い合わせ型の既定値は `A` です。たとえば `AAAA` だけを持つ名前の A/NODATA を試す場合は、`--target-type A` を指定します。NXDOMAIN やワイルドカード応答に必要な不在証明を試す場合は、問い合わせる名前を `--target-name` に指定して `*-cover-mismatch` モードを使います。

DS 関連モードは親ゾーンを、`DNSKEY`・`A`・NSEC/NSEC3 関連モードは子ゾーンを対象にします。同じ委任先の複数の失敗パターンを作る場合は、毎回、正常なゾーンから始めてください。署名の前後どちらで加工するかはモードによって異なります。

署名済みゾーンに `nsec-*` モードを実行すると、変更した NSEC/NSEC3 RRset の RRSIG だけを再生成します。再署名には `--zsk-private-key` で指定した ZSK、または `--key-directory` から選んだ ZSK を使います。`--sign-zone` を指定した場合は、ゾーンに署名してから対象を加工し、同じく変更した RRset だけを再署名します。`--key-directory` を使う場合は、対応アルゴリズム（RSASHA256、ECDSAP256SHA256、ED25519、ED448、MLDSA44）の `.key` と `.private` を同じディレクトリに置いてください。MLDSA44 の `.private` は、32 バイトの seed を Base64 化した `PrivateKey:` を含む形式です。MLDSA44 の DNSSEC 対応は、アルゴリズム番号 18 を定める [IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-westerbaan-dnssec-mldsa/) に基づきます。

`nsec3-* --sign-zone` は NSEC を生成せず、NSEC3 チェーンを作って署名します。チェーンの型ビットマップには、署名対象 RRset に付く `RRSIG` も含めます。empty non-terminal（配下に名前はあるが、その名前自身にはレコードがない名前）もチェーンに含めますが、委任先の glue と委任配下のデータは署名・ハッシュ化しません。委任の NS は署名せず、DS がある場合だけ署名します。

既存の `NSEC3PARAM` があれば、そのアルゴリズム・反復回数・salt を使います。なければ SHA-1、反復回数 0、salt なしを使います。`--nsec3-iterations` と `--nsec3-salt` を指定すると、対応する既存値を上書きできます。反復回数 1 を使う場合は `--nsec3-iterations 1` を指定してください。NSEC3 の再生成時は既存の NSEC/NSEC3 と RRSIG を取り除き、チェーンを作り直します。`nsec3-optout-cover-mismatch --sign-zone` では DS のない委任のハッシュを省略し、Opt-Out フラグ付きの範囲を生成します。

`nsec-cover-mismatch` と `nsec3-cover-mismatch` は、NXDOMAIN などに必要なカバー範囲を壊します。範囲の終端は範囲に含まれないため、Next を対象名（NSEC3 では対象名のハッシュ）にします。Next を所有者自身にすると循環範囲が広がり、不在証明が成立する場合があるため、自己ループは使いません。加工後は変更した RRset の署名を再生成します。`nsec3-optout-cover-mismatch` は、対象名を覆う Opt-Out NSEC3 がある場合に、その DS 不在証明を壊します。

## 実行例

親ゾーン `example.test.` の `keytag.ds.error.example.test.` 委任にある DS を加工してから署名します。

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

同じ親ゾーンで、DS の Digest 不整合と DS の署名破損を作る例です。`ds-rrsig-corrupt` は署名後に `RRSIG DS` を加工します。

```bash
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-hash.zone.signed -d example.test. -m ds-hash-mismatch -t hash.ds.error.example.test. -k /path/to/keys --sign-zone
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-rrsig.zone.signed -d example.test. -m ds-rrsig-corrupt -t sign.ds.error.example.test. -k /path/to/keys --sign-zone
```

子ゾーン `sign.dnskey.error.example.test.` に署名し、DNSKEY の署名を加工します。このモードでは `--target-name` は不要です。

```bash
.venv/bin/python corrupt_zone.py \
  --input sign.dnskey.error.example.test.zone \
  --output sign.dnskey.error.example.test.zone.signed \
  --origin sign.dnskey.error.example.test. \
  --mode dnskey-rrsig-corrupt \
  --key-directory /path/to/keys \
  --sign-zone
```

有効期限切れにするには、`--mode dnskey-rrsig-expired` を指定します。

```bash
.venv/bin/python corrupt_zone.py -i expire.dnskey.error.example.test.zone -o expire.dnskey.error.example.test.zone.signed -d expire.dnskey.error.example.test. -m dnskey-rrsig-expired -k /path/to/keys --sign-zone
```

存在しない `missing.error.example.test.` を覆う NSEC の範囲を壊し、変更した NSEC RRset だけを再署名する例です。

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

NSEC3 を使う場合は `--mode nsec3-cover-mismatch` を指定します。`--sign-zone` を指定すると、NSEC3 チェーンの生成と署名の後にカバー範囲を加工します。

Opt-Out NSEC3 の範囲を壊す場合は `--mode nsec3-optout-cover-mismatch` を指定します。対象名は、変更する Opt-Out NSEC3 が実際に覆う名前にしてください。

入力ゾーンに DS のない委任 `unsigned IN NS ns.example.test.` があれば、次のように署名・加工できます。署名には Python の dnspython を使うため、`ldns-signzone` は不要です。

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

一括生成スクリプトは、親ゾーンに DS を追加し、`ds-keytag-mismatch` と `ds-hash-mismatch` を適用してから署名します。その後、署名済みゾーンに `ds-rrsig-corrupt` を適用します。通常はスクリプトに任せ、手作業で加工する場合だけ以下の手順を使ってください。

Key Tag と Digest は未署名ファイルで加工してから親ゾーンに署名します。`ds-rrsig-corrupt` は署名済みファイルに適用してください。加工後に再署名すると、破損した署名が修復されます。

```bash
# 未署名ゾーンの DS を加工（必要な加工をすべて行ってから署名）
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.zone.work1 -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test.
.venv/bin/python corrupt_zone.py -i example.test.zone.work1 -o example.test.zone.work2 -m ds-hash-mismatch -d example.test. -t hash.ds.error.example.test.

# example.test.zone.work2 を署名し、出力を example.test.zone.signed とした場合
.venv/bin/python corrupt_zone.py -i example.test.zone.signed -o example.test.zone.final -m ds-rrsig-corrupt -d example.test. -t sign.ds.error.example.test.
```

検証ケースごとに独立したゾーンファイルを作る場合は、毎回、正常な未署名ゾーンから始めます。加工したファイルを NSD に読み込ませてください。

複数のケースをまとめて作る場合は、次の一括生成スクリプトを利用できます。

## 補助スクリプト

`scripts/` には、一連の処理を実行する POSIX `sh` スクリプトと、個別の工程を担うスクリプトがあります。通常は一括生成スクリプトを使い、特定の工程だけ実行する場合は表の個別スクリプトを使ってください。

| スクリプト | 用途・入出力 |
| --- | --- |
| [`dnssec_generate_error_zones.sh`](scripts/dnssec_generate_error_zones.sh) | 一括実行。テンプレートからゾーンを生成し、子ゾーン署名・加工、親ゾーンへの DS 追加・加工・署名、NSEC/NSEC3 ケース作成まで行う。`--key-dir`、`--template-dir`、`--output-dir` で各ディレクトリを指定する |
| [`dnssec_make_error_zonefiles.sh`](scripts/dnssec_make_error_zonefiles.sh) | テンプレートから親・子の未署名ゾーンファイルだけを生成する。署名や DS 追加はしない。`--template-dir`、`--output-dir` を指定できる |
| [`dnssec_sign_child_zones.sh`](scripts/dnssec_sign_child_zones.sh) | 指定したベースゾーン名に一致する子ゾーンファイルを一括署名し、各入力に `.signed` を付けたファイルを作る。テンプレートは署名対象外 |
| [`dnssec_sign_zone.sh`](scripts/dnssec_sign_zone.sh) | 1つのゾーンファイルを `corrupt_zone.py` で署名し、入力ファイル名に `.signed` を付けて出力する |
| [`dnssec_corrupt_child_zone.sh`](scripts/dnssec_corrupt_child_zone.sh) | 対応する子ゾーンの DNSKEY 署名破損・期限切れ、または A 署名破損のファイルを作成する。テンプレートディレクトリを第2引数に指定できる |
| [`dnssec_corrupt_parent_zone.sh`](scripts/dnssec_corrupt_parent_zone.sh) | 親ゾーンファイルを指定モード（`ds-keytag-mismatch`、`ds-hash-mismatch`、`ds-rrsig-corrupt`）で加工し、入力ファイルを更新する |
| [`dnssec_nsec_corrupt_zone.sh`](scripts/dnssec_nsec_corrupt_zone.sh) | NSEC/NSEC3 ケースを署名・加工する。型ビットマップ用に `--target-type`、NSEC3 用に `--nsec3-iterations` と `--nsec3-salt` を指定できる。反復回数は既存の `NSEC3PARAM` に従い、なければ 0。既存の `.signed` は `.signed.orig` に退避される |
| [`dnssec_add_ds_records.py`](scripts/dnssec_add_ds_records.py) | 親ゾーン内の NS 委任を確認し、鍵ディレクトリの `.ds` ファイルから DS を追加する。親ゾーンファイルを直接更新する |
| [`dnssec_mldsa_keygen.py`](scripts/dnssec_mldsa_keygen.py) | MLDSA44 (DNSSEC アルゴリズム 18) の KSK/ZSK と、KSK の DS を鍵ディレクトリに生成する |

一括生成スクリプトは、任意の作業ディレクトリから次のように実行できます。

```sh
PYTHON=.venv/bin/python \
  sh /path/to/dnssec-corrupt-zone/scripts/dnssec_generate_error_zones.sh \
  example.test.zone --key-dir /path/to/keys --output-dir /path/to/output
```

テンプレートの既定の場所はリポジトリの `templates/` です。別の場所を使う場合は `--template-dir DIR`、生成先を指定する場合は `--output-dir DIR` を指定します。相対パスはコマンド実行時のカレントディレクトリを基準に解決し、出力先がなければ作成します。`dnssec_make_error_zonefiles.sh` でも同じオプションを使えます。

独自のテンプレートディレクトリには、`template.<base-zone>.zone`（親）、`template.algorithm.<base-zone>.zone`（通常の子）、`template.optout.algorithm.<base-zone>.zone`（Opt-Out 用の子）を用意してください。親テンプレートには、生成する各アルゴリズムの子ゾーン委任も必要です（`rsasha256`、`ecdsap256sha256`、`ed25519`、`ed448`、`mldsa44`）。Opt-Out 用テンプレートには、`unsigned` という名前の NS 委任を置き、DS は置きません。

`PYTHON` には Python 実行ファイルを指定できます（既定値: `python3`）。鍵ディレクトリは `--key-dir DIR` または環境変数 `DNSSEC_KEY_DIR` で指定でき、オプションが環境変数より優先されます。どちらも未指定の場合は、実行時のカレントディレクトリから見た `../keys` を使います。スクリプト本体と `corrupt_zone.py` はスクリプトの配置場所から検索します。一部の個別スクリプトでは `DNSSEC_ZONE_DIR` でゾーンディレクトリも指定できます。署名には dnspython と cryptography を使います。

`ldns-keygen` が対応していない環境でも MLDSA44 鍵を生成できるよう、dnspython と cryptography を使う `dnssec_mldsa_keygen.py` を用意しています。ゾーン名と出力先を指定すると、KSK（flags 257）と ZSK（flags 256）の `.key` / `.private`、および KSK の SHA-256 `.ds` を作成します。

```sh
python=.venv/bin/python
key_dir=/path/to/keys
"$python" scripts/dnssec_mldsa_keygen.py example.test --key-directory "$key_dir"
```

`.private` には `Algorithm: 18 (MLDSA44)` と、32 バイトの seed を Base64 化した `PrivateKey:` を記録します。秘密鍵ファイルは所有者だけが読み書きできる権限で作成し、既存ファイルは上書きしません。鍵ローテーションでは新しいファイルを別途管理してください。生成した鍵は署名スクリプトや親ゾーンの DS 追加処理で利用できます。

`dnssec_make_error_zonefiles.sh` は、NSEC/NSEC3 の型ビットマップ不整合について、A のほか MX と TXT を問い合わせ型にしたゾーンも生成します。NSEC3 のカバー不成立、型ビットマップ不整合、Opt-Out カバー不成立には、次の4種類のパラメーターを使います。

| ゾーン名の追加部分 | NSEC3 反復回数 | NSEC3 salt |
| --- | ---: | --- |
| `iter0.nosalt` | 0 | なし |
| `iter0.saltA1B2` | 0 | `A1B2` |
| `iter1.nosalt` | 1 | なし |
| `iter1.saltA1B2` | 1 | `A1B2` |

たとえば `cover.mismatch.nsec3.iter1.saltA1B2.rsasha256.<zone>.zone` は、反復回数 1、salt `A1B2` の NSEC3 ゾーンでカバー不成立を作ります。一括生成スクリプトで署名と DS 追加まで行う場合は、各委任先の `.key`、`.private`、`.ds` が鍵ディレクトリに必要です。未署名ゾーンだけを作る場合は `dnssec_make_error_zonefiles.sh` を使います。

`dnssec_nsec_corrupt_zone.sh` では、`--target-type TYPE` でビットマップに追加する型を指定できます。`--nsec3-iterations COUNT` と `--nsec3-salt HEX` は NSEC3 の署名パラメーターを指定します。salt は偶数桁の16進数です。次の例では、反復回数 1、salt `A1B2` の NSEC3 ゾーンを作ります。

```sh
sh scripts/dnssec_nsec_corrupt_zone.sh \
  cover.mismatch.nsec3.iter1.saltA1B2.rsasha256.example.test.zone \
  nsec3-cover-mismatch cover.mismatch.nsec3.iter1.saltA1B2.rsasha256.example.test \
  /path/to/keys . \
  --nsec3-iterations 1 --nsec3-salt A1B2
```

一括生成スクリプトは、親ゾーンテンプレートをコピーした後、各 NS 委任に対応する `.ds` ファイルから DS を追加します。ファイル名は `K<child-zone>.+*.ds` とし、鍵ディレクトリは `--key-dir` または `DNSSEC_KEY_DIR` で指定します。ファイルの内容には `ldns-key2ds` のゾーン形式出力を使います（例: `ldns-key2ds Kchild.example.+008+12345.key > Kchild.example.+008+12345.ds`）。各ファイルに委任先の DS だけが含まれることを確認し、欠落や不一致があればエラー終了します。ロールオーバー中の複数 DS はすべて追加し、既存と一致する DS は重複追加しません。既存 DS がファイル群に含まれない場合もエラーになります。

子ゾーンの origin は、ファイル名から末尾の `.zone` を除いた名前です。たとえば `sign.dnskey.error.ed25519.example.test.zone` の origin は `sign.dnskey.error.ed25519.example.test` で、この名前に対応する鍵を使います。ベースゾーン名 `example.test` は親ゾーンの処理に使います。

補助スクリプトの引数や鍵選択は、次のテストで確認できます。通常のテストでは外部コマンドをスタブに置き換えます。`ldns-keygen` がインストールされている場合は、実鍵による NSEC3 署名と Opt-Out ケースの検証も行います。

```sh
.venv/bin/python -m unittest -v test_shell_scripts.py test_dnssec_add_ds_records.py
```

`ldns-keygen` がない場合は、実鍵を使うテストだけスキップします。

## テスト

NSEC/NSEC3 のカバー範囲、NODATA 型ビットマップ、NSEC3 Opt-Out の加工は、次のコマンドで検証できます。

```bash
.venv/bin/python -m unittest -v test_corrupt_zone.py
```

テストでは、NSEC/NSEC3 のチェーンと型ビットマップ、empty non-terminal、委任・glue の扱いを確認します。また、加工後の署名を検証し、変更対象以外の RRset が保たれることも確認します。`ldns-verify-zone` がインストールされている場合は、正常系のゾーン構造を別実装でも検証します。

全テストを実行するには、次のコマンドを使います。

```bash
.venv/bin/python -m unittest -v
```

### Opt-Out ケースの仕組みと比較方法

生成するゾーンの構造は次のとおりです。

```text
dnssec-check.jp.
  └─ optout.mismatch.nsec3.rsasha256.dnssec-check.jp.  ← DS のある署名済みゾーン
       └─ unsigned                                     ← NS だけの未署名委任、DS なし
```

未署名委任 `unsigned` に対応する NSEC3 は省略し、そのハッシュを覆う NSEC3 に Opt-Out フラグを立てます。バリデータはこのフラグから、範囲内に DS のない委任があり得ることを判断し、`unsigned` への DS 問い合わせに対する不在証明を検証します。これは、通常の NXDOMAIN や AAAA だけを持つ名前への A/NODATA とは異なるケースです。

`nsec3-optout-cover-mismatch --sign-zone` は Opt-Out NSEC3 チェーンを生成・署名した後、`unsigned` を覆う NSEC3 の Next を `unsigned` 自身のハッシュに変更します。範囲の終端はカバー対象に含まれないため、DS 不在証明が成立しなくなります。変更した NSEC3 RRset とその RRSIG だけを再生成するため、署名そのものの検証失敗とは区別できます。委任の NS と glue は署名しません。

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
- 署名および RRSIG の再生成は RSASHA256 (8)、ECDSAP256SHA256 (13)、ED25519 (15)、ED448 (16)、MLDSA44 (18) の鍵に対応しています。MLDSA44 の DNSSEC 仕様は IETF Internet-Draft に基づきます。
