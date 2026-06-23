# alchemy-auth

[AlchemyEngine](https://github.com/FRICK-ELDY/alchemy-engine) 向けの **ユーザー認証 API** サービス。

登録・ログイン・セッション検証・ログアウトを担い、ゲームエンジン本体やアセット管理サービスから **認証責務を分離** する。

## 目的

| 責務 | 説明 |
|:---|:---|
| ユーザーアイデンティティ | UUID ベースのユーザー ID（JWT `sub`） |
| 登録 / ログイン | メール + パスワード（Argon2） |
| セッション | JWT（Bearer）の発行・検証 |
| ログアウト | トークン失効（`jti` ベース） |

**本リポジトリが担わないもの**

- ゲームロジック・ルーム管理（[alchemy-engine](https://github.com/FRICK-ELDY/alchemy-engine)）
- アセットメタデータ・BLOB 管理（将来の alchemy-assets）
- ログイン UI（alchemy-engine クライアント側）

## アーキテクチャ上の位置

```
┌─────────────────┐     JWT (Bearer)      ┌─────────────────┐
│  alchemy-engine │ ◄──────────────────── │  alchemy-auth   │
│  (ゲーム/UI)    │     JWKS 公開鍵参照    │  (本リポ)        │
└─────────────────┘                       └─────────────────┘
        │                                         │
        │ 将来                                    │ 将来
        ▼                                         ▼
┌─────────────────┐                       ┌─────────────────┐
│ alchemy-assets  │ ◄── JWT sub = owner ──│   PostgreSQL    │
│ (Ash + メタ)    │                       │   (users 等)    │
└─────────────────┘                       └─────────────────┘
```

- **User の SSoT** は本サービスのみ。他サービスは JWT の `sub`（ユーザー UUID）だけを参照する。
- ルーム参加用の短命トークン（Room Token）は alchemy-engine 側が発行する（User Session → Room Token の 2 段階）。

## 技術スタック

| 項目 | バージョン |
|:---|:---|
| Elixir | ~> 1.19 |
| Erlang/OTP | 28 |
| Phoenix | ~> 1.8 |
| Ash + ash_postgres | ~> 3.0 / ~> 2.0 |
| PostgreSQL | 16+ |
| パスワードハッシュ | Argon2 |
| セッション | JWT（RS256） |

## MVP スコープ

### 含む

1. `users` テーブル（`id` UUID, `email`, `password_hash`, `status`）
2. ユーザー登録（email 一意制約）
3. メール + パスワードログイン
4. JWT セッション発行
5. 認証済み API ガード（`GET /me`）
6. ログアウト（トークン失効）

### 含まない（後フェーズ）

- メール確認・パスワードリセット
- OAuth / OIDC
- リフレッシュトークン
- alchemy-engine / alchemy-assets との本番統合
- 管理画面

## API（v1）

| Method | Path | 認証 | 説明 |
|:---|:---|:---|:---|
| `POST` | `/api/v1/auth/register` | なし | ユーザー登録 |
| `POST` | `/api/v1/auth/login` | なし | ログイン → JWT 発行 |
| `POST` | `/api/v1/auth/logout` | Bearer | ログアウト |
| `GET` | `/api/v1/auth/me` | Bearer | 認証済みユーザー情報 |
| `GET` | `/health` | なし | ヘルスチェック |
| `GET` | `/.well-known/jwks.json` | なし | JWT 検証用公開鍵 |

### リクエスト / レスポンス例

**Register**

```http
POST /api/v1/auth/register
Content-Type: application/json

{"email": "user@example.com", "password": "secret123"}
```

```json
HTTP/1.1 201 Created

{"user_id": "550e8400-e29b-41d4-a716-446655440000", "email": "user@example.com"}
```

**Login**

```http
POST /api/v1/auth/login
Content-Type: application/json

{"email": "user@example.com", "password": "secret123"}
```

```json
HTTP/1.1 200 OK

{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

**Me**

```http
GET /api/v1/auth/me
Authorization: Bearer eyJ...
```

```json
HTTP/1.1 200 OK

{"user_id": "550e8400-...", "email": "user@example.com", "status": "active"}
```

## JWT クレーム

ログイン成功時に発行する Payload の固定項目:

| クレーム | 説明 | 例 |
|:---|:---|:---|
| `sub` | ユーザー UUID（他サービスの `owner_user_id` と一致） | `"550e8400-..."` |
| `status` | ユーザー状態 | `"active"` |
| `iss` | 発行者 | `"alchemy-auth"` |
| `aud` | 受信者 | `"alchemy-platform"` |
| `iat` | 発行時刻（Unix 秒） | `1719148167` |
| `exp` | 失効時刻（Unix 秒） | `1719234567` |
| `jti` | トークン一意 ID（ログアウト失効用） | `"7c9e6679-..."` |

- 署名方式: **RS256**（本サービスのみ秘密鍵を保持）
- 他サービス（alchemy-engine, alchemy-assets）は `/.well-known/jwks.json` の公開鍵で検証する
- **パスワード・password_hash は JWT に含めない**

## セキュリティ方針

- パスワードは Argon2 ハッシュのみ保存（平文禁止）
- ログイン失敗時は常に同じエラーメッセージ（ユーザー列挙の防止）
- ログイン / 登録にレート制限（目標: 5 回 / 15 分 / IP）
- `status` が `suspended` / `deleted` のユーザーはログイン・JWT 検証の両方で拒否

## ローカル開発

### 前提

- Elixir 1.19 / OTP 28
- Docker（PostgreSQL 用）

### 起動（Docker 一式）

PostgreSQL と Phoenix をまとめて起動する場合:

```bash
docker compose up -d --build
```

初回はイメージビルドと `mix ash.setup` / `ecto.create` / `ecto.migrate` が走るため、数分かかることがあります。`http://localhost:4002/health` で確認できます。

ソースはコンテナに bind mount されるため、コード変更はホスト側で保存すれば `mix phx.server` が再コンパイルします（`deps` / `_build` は名前付きボリュームで永続化）。

### 起動（ホストで Elixir を実行）

PostgreSQL のみ Docker、Elixir は WSL / ローカルで動かす場合:

```bash
# PostgreSQL のみ
docker compose up -d postgres

# 依存関係・DB
mix deps.get
mix ecto.create
mix ecto.migrate

# サーバー起動（デフォルト port 4002）
mix phx.server
```

### スモークテスト

```powershell
curl -X POST http://localhost:4002/api/v1/auth/register `
  -H "Content-Type: application/json" `
  -d '{"email":"test@example.com","password":"secret123"}'

curl -X POST http://localhost:4002/api/v1/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"test@example.com","password":"secret123"}'
```

## 環境変数

| 変数 | 説明 | 例 |
|:---|:---|:---|
| `DATABASE_URL` | PostgreSQL 接続 URL | ホスト: `...@localhost:5433/...` / Docker 内: `...@postgres:5432/...` |
| `SECRET_KEY_BASE` | Phoenix 秘密鍵 | （`mix phx.gen.secret` で生成） |
| `JWT_PRIVATE_KEY_PATH` | RS256 秘密鍵 PEM パス | `priv/jwt_private.pem` |
| `PORT` | HTTP ポート | `4002` |
| `BIND_ALL` | `0.0.0.0` で待ち受け（Docker 用） | `true` |
| `PHX_SERVER` | サーバープロセスを起動 | `true` |

## ポート方針

| サービス | ポート |
|:---|:---|
| alchemy-auth（本サービス） | **4002** |
| alchemy-engine | 4000 |

## テスト

```powershell
mix test
```

CI では PostgreSQL 16 サービスコンテナ上で `mix ecto.create` → `mix ecto.migrate` → `mix test` を実行する。

## 関連リポジトリ

| リポジトリ | 関係 |
|:---|:---|
| [alchemy-engine](https://github.com/FRICK-ELDY/alchemy-engine) | ゲームエンジン。JWT 検証後に Room Token を発行 |
| [alchemy-protocol](https://github.com/FRICK-ELDY/alchemy-protocol) | ゲームワイヤ契約（Protobuf） |
| alchemy-assets（予定） | アセットメタデータ。JWT `sub` を `owner_user_id` として参照 |

## ライセンス

（alchemy-engine と同じライセンスを適用予定）

## ステータス

🚧 **初期開発中** — Ash リソース・JWT・認証 API まで実装済み。CI 整備中。
