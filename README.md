# dnssec-corrupt-zone

署名済みの DNSSEC ゾーンファイルを検証用に加工する Python スクリプトです。親ゾーンの `DS` レコードまたは子ゾーン頂点の `DNSKEY` を覆う `RRSIG` を意図的に壊します。[DNSSEC委任状態検証ツール](https://www.on-link.jp/dnssecvalidator/) で、実際に壊れた事例を確認することができます。

このツールはゾーンへの署名や NSD の再読み込みを行いません。必要に応じて、あらかじめ署名済みのゾーンファイルを入力として用意し、出力ファイルを NSD の設定で読み込ませてください。

## 必要環境

- Python 3.10 以降
- `dnspython` 2.6 以降、3 未満
- 署名済みの親ゾーン・子ゾーンファイル

依存関係をインストールします。

```powershell
python -m pip install -r requirements.txt
```

`uv` を使用する場合は次のコマンドでもインストールできます。

```powershell
uv pip install -r requirements.txt
```

## 使い方

```text
python corrupt_zone.py --input INPUT --output OUTPUT --origin ZONE_ORIGIN --mode MODE [--target-name NAME]
```

| 引数 | 説明 |
| --- | --- |
| `--input`, `-i` | 加工前の署名済みゾーンファイル |
| `--output`, `-o` | NSD に読み込ませる加工後ゾーンファイル |
| `--origin`, `-d` | 入力ゾーンのオリジン。末尾の `.` は省略可能 |
| `--mode`, `-m` | 下記の検証ケース |
| `--target-name`, `-t` | 親ゾーンの `DS` を変更する委任先の名前。`ds-*` モードでは必須 |

出力先ディレクトリが存在しない場合は作成されます。対象レコードが見つからない場合、ゾーンを出力せずエラー終了します。

## 検証ケース

| `--mode` | 加工するゾーン | 内容 | dnssec-check.jp の対応パターン |
| --- | --- | --- | --- |
| `success` | 親または子 | 変更せず出力 | 成功パターン |
| `ds-keytag-mismatch` | 親 | 委任先 `DS` の Key Tag を1増やす | Key Tagミスマッチ |
| `ds-hash-mismatch` | 親 | 委任先 `DS` の Digest の末尾1バイトを反転する | ハッシュ値ミスマッチ |
| `ds-rrsig-corrupt` | 親 | 委任先 `DS` を覆う `RRSIG` の署名値を破損する | DSリソースレコードの検証失敗 |
| `dnskey-rrsig-corrupt` | 子 | ゾーン頂点の `DNSKEY` を覆う `RRSIG` の署名値を破損する | DNSKEYリソースレコードの検証失敗 |
| `dnskey-rrsig-expired` | 子 | ゾーン頂点の `DNSKEY` を覆う `RRSIG` の有効期限を `2010-01-01T00:00:00Z` にする | DNSKEYリソースレコードの検証失敗（有効期限切れ） |

`DS` は親ゾーンにあり、`DNSKEY` は子ゾーンにあります。同じ委任先について複数の失敗パターンを公開する場合は、毎回元の正常な署名済みゾーンから個別に出力してください。

## 実行例

親ゾーン `example.test.` にある `keytag.ds.error.example.test.` への委任の DS を壊します。

```powershell
python corrupt_zone.py `
  --input example.test.signed `
  --output example.test.ds-keytag.zone `
  --origin example.test. `
  --mode ds-keytag-mismatch `
  --target-name keytag.ds.error.example.test.
```

同じ親ゾーンから、DS の Digest 不整合と DS の署名破損を作成する例です。

```powershell
python corrupt_zone.py -i example.test.signed -o example.test.ds-hash.zone.signed -d example.test. -m ds-hash-mismatch -t hash.ds.error.example.test.
python corrupt_zone.py -i example.test.signed -o example.test.ds-rrsig.zone.signed -d example.test. -m ds-rrsig-corrupt -t sign.ds.error.example.test.
```

子ゾーン `sign.dnskey.error.example.test.` の DNSKEY 署名を壊します。子ゾーンでは `--target-name` は不要です。

```powershell
python corrupt_zone.py `
  --input sign.dnskey.error.example.test.signed `
  --output sign.dnskey.error.example.test.rrsig-corrupt.zone.signed `
  --origin sign.dnskey.error.example.test. `
  --mode dnskey-rrsig-corrupt
```

有効期限切れのケースは `--mode dnskey-rrsig-expired` を指定します。

```powershell
python corrupt_zone.py -i expire.dnskey.error.example.test.signed -o expire.dnskey.error.example.test.rrsig-expired.zone.signed -d expire.dnskey.error.example.test. -m dnskey-rrsig-expired
```

## NSD への反映

各出力ファイルを NSD の `zonefile:` に指定し、設定を検証してから再読み込みします。実際のコマンドは NSD の導入方法・権限設定に合わせてください。

```text
zone:
    name: "sign.dnskey.error.example.test."
    zonefile: "sign.dnskey.error.example.test.rrsig-corrupt.zone.signed"
```

変更後は `nsd-checkconf` で設定とゾーンを確認し、NSD を再読み込みします。公開環境では、失敗パターン用の委任先を正常系とは別のゾーンとして構成してください。

## 注意事項

- 出力ゾーンは意図的に DNSSEC 検証に失敗します。通常の本番ゾーンには使用しないでください。
- このスクリプトは DNSSEC の署名を再計算しません。加工後の `DS` または `RRSIG` の整合性が壊れることが目的です。
- 署名アルゴリズムに依存しない加工のため、RSASHA256、ECDSAP256SHA256、ED25519、ED448 の各ケースに利用できます。

## 親ゾーンの更新について

親ゾーンについては、`DS` の Key Tag やハッシュ値を先に変更してから親ゾーンを署名することで、個別に事象を発生させることができます。

1. example.test.zone を編集
1. `cp -p example.test.zone example.test.zone.orig`
1. `python corrupt_zone.py -i example.test.zone -o example.test.ds-keytag.zone -m ds-keytag-mismatch -d example.test. -t keytag.ds.error.example.test.`
1. `python corrupt_zone.py -i example.test.ds-keytag.zone -o example.test.ds-hash.zone -m ds-hash-mismatch -d example.test. -t hash.ds.error.example.test.`
1. `cp -p example.test.ds-hash.zone example.test.zone`
1. example.test.zone を署名
1. `python corrupt_zone.py -i example.test.zone.signed -o example.test.zone.ds-rrsig.signed -m ds-rrsig-corrupt -d example.test. -t sign.ds.error.example.test.`
1. `cp -p example.test.zone.ds-rrsig.signed example.test.zone.signed`
1. 権威サーバーでゾーンファイルを再読み込み
