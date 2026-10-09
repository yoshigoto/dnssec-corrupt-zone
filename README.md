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
.venv/bin/python corrupt_zone.py --input INPUT --output OUTPUT --origin ZONE_ORIGIN --mode MODE [--target-name NAME] [--target-type TYPE] [--zsk-private-key PRIVATE_FILE] [--key-directory KEY_DIR] [--sign-zone] [--increment-serial]
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
| `--increment-serial`, `-s` | SOA レコードの Serial を 1 インクリメントする |

出力先ディレクトリが存在しない場合は作成されます。対象レコードが見つからない場合、ゾーンを出力せずエラー終了します。

## 検証ケース

| `--mode` | 加工するゾーン | 内容 | dnssec-check.jp の対応パターン |
| --- | --- | --- | --- |
| `success` | 親または子 | 変更せず出力 | 成功パターン |
| `ds-keytag-mismatch` | 親 | 委任先 `DS` の Key Tag を1増やす | Key Tag ミスマッチ |
| `ds-hash-mismatch` | 親 | 委任先 `DS` の Digest の末尾 1バイトを反転する | ハッシュ値ミスマッチ |
| `ds-rrsig-corrupt` | 親 | 委任先 `DS` の電子署名データである `RRSIG` の署名値を破損する | DS リソースレコードの検証失敗 |
| `dnskey-rrsig-corrupt` | 子 | ゾーンの頂点の `DNSKEY` の電子署名データである `RRSIG` の署名値を破損する | DNSKEY リソースレコードの検証失敗 |
| `dnskey-rrsig-expired` | 子 | ゾーンの頂点の `DNSKEY` の電子署名データである `RRSIG` の有効期限を `2010-01-01T00:00:00Z` にする | DNSKEY リソースレコードの検証失敗（有効期限切れ） |
| `a-rrsig-corrupt` | 子 | 指定名の `A` の電子署名データである `RRSIG` の署名値を破損する | A リソースレコードの検証失敗 |
| `nsec-cover-mismatch` | 子 | 指定名を覆う NSEC の Next Domain Name を指定名にして、指定名をカバーしない状態にする | 不在証明のカバー不成立 |
| `nsec3-cover-mismatch` | 子 | 指定名を覆う NSEC3 の Next Hashed Owner Name を指定名のハッシュにして、指定名をカバーしない状態にする | 不在証明のカバー不成立 |
| `nsec3-optout-cover-mismatch` | 子 | 指定名を覆う Opt-Out フラグ付き NSEC3 だけを対象に、カバー範囲を壊す | Opt-Out 不在証明のカバー不成立 |
| `nsec-type-bitmap-mismatch` | 子 | 指定名の NSEC 型ビットマップに問い合わせ型を追加する | NODATA 不在証明の不整合 |
| `nsec3-type-bitmap-mismatch` | 子 | 指定名の NSEC3 型ビットマップに問い合わせ型を追加する | NODATA 不在証明の不整合 |

加工対象となる `DS` は親ゾーンのものであり、加工対象となる `RRSIG` は子ゾーンのものです。同じ委任先について複数の失敗パターンを公開する場合は、毎回、元の正常な署名済みゾーンから個別に出力してください。

`nsec-*` モードを署名済みゾーンに対して実行する場合は、NSEC/NSEC3 の RDATA を変更した後、`--zsk-private-key` で指定した ZSK、または `--key-directory` から自動選択した ZSK を使って変更対象 RRset の RRSIG だけを再生成します。`--sign-zone` を指定した場合は、未署名ゾーンに NSEC/NSEC3 を生成してからゾーン全体を署名し、その後に NSEC/NSEC3 を壊して変更対象 RRset の RRSIG だけを再生成します。`--key-directory` を使う場合は、`ldns-keygen` で生成した対応アルゴリズム（RSASHA256、ECDSAP256SHA256、ED25519、ED448）の `.key` と、同じベース名の `.private` を同じディレクトリに配置してください。

`nsec3-* --sign-zone` は、dnspython の RRset 署名機能を使って NSEC3 専用の署名済みゾーンを作り、NSEC は生成しません。DNSKEY と NSEC3PARAM を用意してから、署名後に存在する型をビットマップに反映します。empty non-terminal（配下の名前は存在するが、その名前自身にはレコードがない名前）も NSEC3 の対象に含め、委任先の glue や委任配下のデータは署名・ハッシュ化しません。委任の NS 自体は署名せず、DS がある場合だけ DS を署名します。

NSEC3PARAM がなければ、SHA-1、反復回数 0、salt なしを使用します。既存の NSEC3PARAM が 1 レコードあれば、そのアルゴリズム・反復回数・salt を使います。再署名時は古い NSEC/NSEC3 と RRSIG を取り除いて証明チェーンを作り直します。`nsec3-optout-cover-mismatch --sign-zone` では DS のない委任のハッシュを省略し、Opt-Out フラグ付きの範囲を生成します。

`nsec-cover-mismatch` と `nsec3-cover-mismatch` は、存在しない名前に対する NXDOMAIN 応答のカバー範囲を壊します。`nsec3-optout-cover-mismatch` は、未署名委任への DS 問い合わせで使う Opt-Out 不在証明を壊します。AAAA レコードだけが存在する名前への A 問い合わせのような NODATA 応答には、`*-type-bitmap-mismatch` を使います。対象名のビットマップに A を追加すると、権威サーバーの A/NODATA 応答と不在証明が矛盾します。

カバー範囲の終端は範囲に含まれないため、Next を指定名（NSEC3 では指定名のハッシュ）に変更します。Next を所有者自身にすると循環範囲が広がり、不在証明が検証成功する場合があるため、自己ループは使いません。変更対象 RRset の署名は再生成し、署名値ではなく不在証明の不整合を検証できるようにします。

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

## テスト

NSEC/NSEC3 のカバー範囲、NODATA 型ビットマップ、NSEC3 Opt-Out の加工は、次のコマンドで検証できます。

```bash
.venv/bin/python -m unittest -v test_corrupt_zone.py
```

テストでは、正常な NSEC3 ゾーンの循環チェーン、型ビットマップ、empty non-terminal、委任・glue の扱いと署名を確認してから、加工後も全署名が有効で、指定した NSEC3 RRset だけが変更されることを確認します。署名は対応する 4 アルゴリズムで検証します。`ldns-verify-zone` がある場合は、正常系のゾーン構造を独立した実装でも確認します。

## 補助シェルスクリプト

`scripts/` には FreeBSD `/bin/sh` を含む POSIX `sh` 向けの補助スクリプトがあります。作業ディレクトリは任意で、次のように実行できます。

```sh
PYTHON=.venv/bin/python DNSSEC_KEY_DIR=/path/to/keys \
  sh /path/to/dnssec-corrupt-zone/scripts/dnssec_generate_error_zones.sh \
  example.test.zone --output-dir /path/to/output
```

テンプレートは既定でリポジトリの `templates/` から読み込みます。別の場所を使う場合は `--template-dir DIR`、生成先を指定する場合は `--output-dir DIR` を指定します。どちらも相対パスはコマンド実行時のカレントディレクトリを基準に解決します。出力先は未作成でも作成されます。`dnssec_make_error_zonefiles.sh` 単体にも、同じ `--template-dir` / `--output-dir` オプションを指定できます。

独自のテンプレートディレクトリには、`template.<base-zone>.zone`（親）、`template.algorithm.<base-zone>.zone`（通常の子）、`template.optout.algorithm.<base-zone>.zone`（Opt-Out 用の子）を用意してください。Opt-Out 用テンプレートには、`unsigned` という名前の NS 委任を置き、DS は置きません。

`PYTHON` は Python 実行ファイル、`DNSSEC_KEY_DIR` は鍵ディレクトリを指定します。未指定の場合、Python は `python3`、鍵ディレクトリは実行時のカレントディレクトリから見た `../keys` です。スクリプト本体と `corrupt_zone.py` はスクリプトの配置場所を基準に検索します。個別の署名スクリプトでは `DNSSEC_ZONE_DIR` でゾーンディレクトリも指定できます。署名スクリプトの実行には `ldns-signzone` が PATH 上に必要です。

ゾーン生成スクリプトは、親ゾーンテンプレートをコピーした後、親ゾーンの各子ゾーン委任に対応する `K<child-zone>.+*.ds` ファイルを `DNSSEC_KEY_DIR` から探し、DS レコードを追加します。DS ファイルは `ldns-key2ds` のゾーン形式出力を保存したもの（例: `ldns-key2ds Kchild.example.+008+12345.key > Kchild.example.+008+12345.ds`）を使います。委任先の DS ファイルがない、内容が DS レコードでない、または owner 名が委任先と異なる場合はエラー終了します。鍵ロールオーバーで複数の DS ファイルがある場合はすべて追加し、既に同じ DS がある場合は重複させません。

子ゾーンの origin は、各子ゾーンのファイル名から末尾の `.zone` を除いたドメイン名です。例えば `sign.dnskey.error.ed25519.example.test.zone` は `sign.dnskey.error.ed25519.example.test` として署名・加工し、この子ドメインの鍵を使用します。ベースゾーン名 `example.test` を使うのは親ゾーンの処理だけです。

補助スクリプトの引数と鍵選択は、次の回帰テストで確認できます。このテストは外部コマンドをスタブに置き換え、実際の暗号署名は行いません。

```sh
python3 -m unittest -v test_shell_scripts.py
```

`ldns-keygen` と `ldns-signzone` がある場合は、実鍵で Opt-Out ゾーンを署名・加工し、対象のハッシュが省略されていること、変更した NSEC3 とその RRSIG 以外が維持されることも検証します。これらのコマンドがない場合、その実鍵テストだけスキップします。

### Opt-Out ケースの仕組みと比較方法

生成するゾーンの構造は次のとおりです。

```text
dnssec-check.jp.
  └─ optout.mismatch.nsec3.rsasha256.dnssec-check.jp.  ← DS のある署名済みゾーン
       └─ unsigned                                     ← NS だけの未署名委任、DS なし
```

未署名委任 `unsigned` は存在しますが、Opt-Out ではその名前に一致する NSEC3 を省略できます。その代わり、`unsigned` のハッシュを覆う NSEC3 に Opt-Out フラグを立てます。これにより、バリデータは「この範囲には DS のない未署名委任があり得る」と判断でき、`unsigned` への DS 問い合わせの不在証明を検証できます。通常の存在しない名前に対する NXDOMAIN や、AAAA だけの名前への A/NODATA とは異なるケースです。

`ldns-signzone -n -p` はフラグを立てますが、未署名委任のハッシュを省略しません。そのため [dnssec_sign_optout_zone.py](scripts/dnssec_sign_optout_zone.py) は、委任とその配下のレコードをいったん署名対象から外して NSEC3 を生成し、その後に元の委任レコードを戻します。委任の NS や glue は署名しません。この専用処理には、署名前のゾーンを渡してください。

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

## 親ゾーンの更新について

親ゾーンは、通常利用している署名手順で署名する場合、まず未署名のゾーンに対して `--sign-zone` を付けずに `ds-keytag-mismatch` や `ds-hash-mismatch` を実行し、DS を加工します。必要な加工をすべて終えてから親ゾーンを署名してください。こうすることで、加工後の DS に対する署名が作成されます。

`ds-rrsig-corrupt` は署名済みゾーンに対して実行し、親ゾーンの `RRSIG DS` を壊します。この処理の後に親ゾーンを再署名すると破損した署名が修復されてしまうため、再署名しないでください。`--sign-zone` を使ってツール内で署名する方法もありますが、通常の署名手順を使う場合は次のように実行します。

```bash
# 1件目: 未署名ゾーンの DS Key Tag を加工
.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.zone.work1 -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test.

# 2件目: 同じ未署名ゾーンに別の DS 加工を重ねる
.venv/bin/python corrupt_zone.py -i example.test.zone.work1 -o example.test.zone.work2 -m ds-hash-mismatch -d example.test. -t hash.ds.error.example.test.

# example.test.zone.work2 を通常の署名手順で署名し、example.test.zone.signed を作成
# 署名済みゾーンの DS RRSIG を加工
.venv/bin/python corrupt_zone.py -i example.test.zone.signed -o example.test.zone.final -m ds-rrsig-corrupt -d example.test. -t sign.ds.error.example.test.
```

上の例で、NSD に読み込ませるファイルは最後の `example.test.zone.final` です。中間ファイルは作業用なので、不要になれば削除できます。

各検証ケースを独立したゾーンファイルにする場合は、ケースごとに正常な未署名ゾーンから作業を始め、DS の加工後にそれぞれ通常の手順で署名してください。`ds-rrsig-corrupt` のケースでは、署名済みファイルを入力にして最後に RRSIG を加工します。署名処理の具体的なコマンドは、環境で使用している署名方法に合わせてください。

1. example.test.zone を編集
1. `.venv/bin/python corrupt_zone.py -i example.test.zone -o example.test.ds-keytag.zone -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test.`
1. `example.test.ds-keytag.zone` を通常の署名手順で署名
1. `ds-rrsig-corrupt` のケースでは、署名済みファイルを入力として `.venv/bin/python corrupt_zone.py -i example.test.ds-keytag.zone.signed -o example.test.ds-rrsig.zone.signed -m ds-rrsig-corrupt -d example.test. -t sign.ds.error.example.test.` を実行
1. 権威サーバーでゾーンファイルを再読み込み
