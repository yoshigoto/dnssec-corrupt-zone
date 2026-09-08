# dnssec-corrupt-zone

DNSSEC ゾーンファイルを検証用に加工する Python スクリプトです。親ゾーンの `DS`、子ゾーンの `DNSKEY` と否定応答に使われる NSEC/NSEC3 を意図的に不整合にします。[DNSSEC委任状態検証ツール](https://www.on-link.jp/dnssec-validator/) で、実際に壊れた事例を確認することができます。

このツールは通常、ゾーン全体の署名や NSD の再読み込みを行いません。`nsec-*` モードだけは、指定された ZSK で変更対象 NSEC/NSEC3 RRset の RRSIG を再生成します。必要に応じて署名前、または署名済みのゾーンファイルを用意し、このツールで出力されたゾーンファイルを NSD で読み込ませてください。

なお、本ツールで作成したドメイン名のリストを、[DNSSEC信頼の連鎖確認ページ](https://www.dnssec-check.jp/) で公開しています。

## 必要環境

- Python 3.10 以降
- `dnspython` 2.6 以降、3 未満
- `cryptography` 42 以降
- 親ゾーン・子ゾーンファイル (目的によって署名済みのもの、もしくは未署名のもの)

依存するモジュールをインストールします。

```powershell
python -m pip install -r requirements.txt
```

`uv` を使用する場合は次のコマンドでもインストールできます。

```powershell
uv pip install -r requirements.txt
```

## 使い方

```text
python corrupt_zone.py --input INPUT --output OUTPUT --origin ZONE_ORIGIN --mode MODE [--target-name NAME] [--target-type TYPE] [--zsk-private-key PRIVATE_FILE] [--increment-serial]
```

| 引数 | 説明 |
| --- | --- |
| `--input`, `-i` | 加工対象となるゾーンファイル |
| `--output`, `-o` | NSD に読み込ませる加工後のゾーンファイル |
| `--origin`, `-d` | 入力ゾーンのオリジン (末尾の `.` は省略可能) |
| `--mode`, `-m` | 後述する検証ケース |
| `--target-name`, `-t` | 加工対象の名前 (`ds-*`、`nsec-*` モードでは必須)。`www` のような相対名は `--origin` に対して解決され、末尾に `.` がある名前は FQDN として扱われます |
| `--target-type` | 型ビットマップ不整合モードで追加する問い合わせ型 (既定: `A`) |
| `--zsk-private-key` | `nsec-*` モードで変更した NSEC/NSEC3 RRset を再署名する ZSK の `.private` ファイル (RSA/SHA-256、アルゴリズム番号 8) |
| `--increment-serial`, `-s` | SOA レコードの Serial を 1 インクリメントする |

出力先ディレクトリが存在しない場合は作成されます。対象レコードが見つからない場合、ゾーンを出力せずエラー終了します。

## 検証ケース

| `--mode` | 加工するゾーン | 内容 | dnssec-check.jp の対応パターン |
| --- | --- | --- | --- |
| `success` | 親または子 | 変更せず出力 | 成功パターン |
| `ds-keytag-mismatch` | 親 | 委任先 `DS` の Key Tag を1増やす | Key Tagミスマッチ |
| `ds-hash-mismatch` | 親 | 委任先 `DS` の Digest の末尾 1バイトを反転する | ハッシュ値ミスマッチ |
| `ds-rrsig-corrupt` | 親 | 委任先 `DS` の電子署名データである `RRSIG` の署名値を破損する | DSリソースレコードの検証失敗 |
| `dnskey-rrsig-corrupt` | 子 | ゾーン頂点の `DNSKEY` の電子署名データである `RRSIG` の署名値を破損する | DNSKEYリソースレコードの検証失敗 |
| `dnskey-rrsig-expired` | 子 | ゾーン頂点の `DNSKEY` の電子署名データである `RRSIG` の有効期限を `2010-01-01T00:00:00Z` にする | DNSKEYリソースレコードの検証失敗（有効期限切れ） |
| `nsec-cover-mismatch` | 子 | 指定名を覆う NSEC の Next Domain Name を所有者名にして、指定名をカバーしない状態にする | 不在証明のカバー不成立 |
| `nsec3-cover-mismatch` | 子 | 指定名を覆う NSEC3 の Next Hashed Owner Name を所有者ハッシュにして、指定名をカバーしない状態にする | 不在証明のカバー不成立 |
| `nsec3-optout-cover-mismatch` | 子 | 指定名を覆う Opt-Out フラグ付き NSEC3 だけを対象に、カバー範囲を壊す | Opt-Out 不在証明のカバー不成立 |
| `nsec-type-bitmap-mismatch` | 子 | 指定名の NSEC 型ビットマップに問い合わせ型を追加する | NODATA 不在証明の不整合 |
| `nsec3-type-bitmap-mismatch` | 子 | 指定名の NSEC3 型ビットマップに問い合わせ型を追加する | NODATA 不在証明の不整合 |

加工対象となる `DS` は親ゾーンのものであり、加工対象となる `RRSIG` は子ゾーンのものです。同じ委任先について複数の失敗パターンを公開する場合は、毎回、元の正常な署名済みゾーンから個別に出力してください。

`nsec-*` モードは、**NSEC/NSEC3 とその RRSIG を含む署名済みゾーン**に対して実行します。NSEC/NSEC3 の RDATA を変更した後、`--zsk-private-key` で指定した ZSK を使って変更対象 RRset の RRSIG だけを再生成します。秘密鍵は `ldns-keygen` または `dnssec-keygen` で生成した RSA/SHA-256（アルゴリズム番号 8）の `.private` ファイルを指定してください。未署名ゾーンや NSEC/NSEC3 がないゾーンでは対象レコードを変更できません。

`*-cover-mismatch` は、存在しない名前に対する NXDOMAIN 応答のカバー範囲を壊します。AAAA レコードだけが存在する名前への A 問い合わせのような NODATA 応答には、`*-type-bitmap-mismatch` を使います。対象名のビットマップに A を追加すると、権威サーバーの A/NODATA 応答と不在証明が矛盾します。

ワイルドカード応答の次に近い名前の不在証明も、実際に問い合わせる名前を `--target-name` に指定して `*-cover-mismatch` を使います。NSEC3 Opt-Out を使う委任ケースでは、`nsec3-optout-cover-mismatch` を指定してください。このモードは Opt-Out フラグを持つ NSEC3 が対象名を覆う場合だけ変更します。

## 実行例

親ゾーン `example.test.` にある `keytag.ds.error.example.test.` への委任の DS を壊します。

```powershell
python corrupt_zone.py `
  --input example.test.zone.signed `
  --output example.test.ds-keytag.zone.signed `
  --origin example.test. `
  --mode ds-keytag-mismatch `
  --target-name keytag.ds.error.example.test.
```

同じ親ゾーンで、DS の Digest 不整合と DS の署名破損を作成する例です。

```powershell
python corrupt_zone.py -i example.test.zone.signed -o example.test.ds-hash.zone.signed -d example.test. -m ds-hash-mismatch -t hash.ds.error.example.test.
python corrupt_zone.py -i example.test.zone.signed -o example.test.ds-rrsig.zone.signed -d example.test. -m ds-rrsig-corrupt -t sign.ds.error.example.test.
```

子ゾーン `sign.dnskey.error.example.test.` の DNSKEY 署名を壊します。子ゾーンでは `--target-name` は不要です。

```powershell
python corrupt_zone.py `
  --input sign.dnskey.error.example.test.zone.signed `
  --output sign.dnskey.error.example.test.zone.signed-out `
  --origin sign.dnskey.error.example.test. `
  --mode dnskey-rrsig-corrupt
```

有効期限切れのケースでは `--mode dnskey-rrsig-expired` を指定します。

```powershell
python corrupt_zone.py -i expire.dnskey.error.example.test.zone.signed -o expire.dnskey.error.example.test.zone.signed-out -d expire.dnskey.error.example.test. -m dnskey-rrsig-expired
```

存在しない `missing.error.example.test.` を覆う NSEC のカバー範囲を壊してから署名する例です。

```powershell
python corrupt_zone.py `
  --input error.example.test.zone.signed `
  --output error.example.test.nsec-cover.zone.signed `
  --origin error.example.test. `
  --mode nsec-cover-mismatch `
  --target-name missing.error.example.test. `
  --zsk-private-key /path/to/Kexample.test.+008+12345.private
```

入力の未署名ゾーンから `dnssec_sign_zone.sh` で正常な署名済みゾーンを先に作成し、その出力を `--input` に指定してください。NSEC3 署名済みゾーンを対象にする場合は、同じ対象名に `--mode nsec3-cover-mismatch` を指定します。

Opt-Out NSEC3 のカバー範囲を壊す場合は、`--mode nsec3-optout-cover-mismatch` を指定します。対象名は、変更対象となる Opt-Out NSEC3 が実際に覆う名前にしてください。

AAAA レコードだけを持つ `optout-cover-mismatch.nsec3.error.example.test.` の A/NODATA 不在証明を壊すには、正常に署名済みの子ゾーンに対して次のように実行します。

```powershell
python corrupt_zone.py `
  --input optout-cover-mismatch.nsec3.error.example.test.zone.signed `
  --output optout-cover-mismatch.nsec3.error.example.test.nsec3-bitmap.zone.signed `
  --origin nsec3.error.example.test. `
  --mode nsec3-type-bitmap-mismatch `
  --target-name optout-cover-mismatch.nsec3.error.example.test. `
  --target-type A `
  --zsk-private-key /path/to/Knsec3.error.example.test.+008+12345.private
```

通常の NSEC ゾーンでは `--mode nsec-type-bitmap-mismatch` を指定します。`--target-type` は省略時に `A` となるため、上の例では省略可能です。

## テスト

NSEC/NSEC3 のカバー範囲、NODATA 型ビットマップ、NSEC3 Opt-Out の加工は、次のコマンドで検証できます。

```powershell
python -m unittest -v test_corrupt_zone.py
```

## NSD への反映

各出力ファイルを NSD の `zonefile:` に指定し、変更後は `nsd-checkconf` で設定とゾーンを確認し、NSD を再読み込みします。実際のコマンドは NSD の導入方法・権限設定に合わせてください。

```text
zone:
    name: "sign.dnskey.error.example.test."
    zonefile: "sign.dnskey.error.example.test.zone.signed-out"
```

※公開環境では、失敗パターン用の委任先を正常系とは別のゾーンとして構成してください。

## 注意事項

- 出力ゾーンは意図的に DNSSEC 検証に失敗します。通常利用している本番ゾーンには使用しないでください。
- `nsec-*` モードでは、変更した NSEC/NSEC3 RRset の RRSIG だけを ZSK で再生成します。それ以外の署名は再計算しません。
- RRSIG の再生成は RSA/SHA-256（アルゴリズム番号 8）の ZSK に対応しています。

## ゾーンファイルへの署名について

未署名のゾーンファイルから署名済みゾーンファイルを生成するためのシェルスクリプト `dnssec_sign_zone.sh` を利用できます。
このスクリプトは `ldns-signzone` を用いて、指定された鍵ディレクトリから KSK（フラグ 257）および ZSK（フラグ 256）を自動識別してゾーンに署名します。

### 使い方

```bash
./dnssec_sign_zone.sh <zone_file_name> [key_dir] [zone_dir]
```

| 引数 | 説明 | デフォルト値 |
| --- | --- | --- |
| `<zone_file_name>` | 署名対象のゾーンファイル名 | (必須) |
| `[key_dir]` | KSK / ZSK 鍵ファイルが配置されているディレクトリ | `/usr/local/etc/nsd/keys` |
| `[zone_dir]` | ゾーンファイルが配置されているディレクトリ | `/usr/local/etc/nsd/zone` |

### 実行例

デフォルトのディレクトリ設定で署名する場合:

```bash
./dnssec_sign_zone.sh example.test.zone
```

鍵ディレクトリやゾーンファイルのディレクトリを指定する場合:

```bash
./dnssec_sign_zone.sh example.test.zone /path/to/keys /path/to/zones
```

実行が成功すると、対象のゾーンファイルが存在するディレクトリに `<zone_file_name>.signed` （例: `example.test.zone.signed`）が生成されます。

## 親ゾーンの更新について

親ゾーンについては、`DS` の Key Tag やハッシュ値を先に変更してから親ゾーンを署名することで、個別に事象を発生させることができます。

1. example.test.zone を編集
1. `cp -p example.test.zone example.test.zone.orig`
1. `python corrupt_zone.py -i example.test.zone -o example.test.ds-keytag.zone -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test.`
1. `python corrupt_zone.py -i example.test.ds-keytag.zone -o example.test.ds-hash.zone -m ds-hash-mismatch -d example.test. -t hash.ds.error.example.test.`
1. `cp -p example.test.ds-hash.zone example.test.zone`
1. example.test.zone を署名 (`dnssec_sign_zone.sh` を利用)
1. `python corrupt_zone.py -i example.test.zone.signed -o example.test.zone.ds-rrsig.signed -m ds-rrsig-corrupt -d example.test. -t sign.ds.error.example.test.`
1. `cp -p example.test.zone.ds-rrsig.signed example.test.zone.signed`
1. 権威サーバーでゾーンファイルを再読み込み
