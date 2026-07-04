# 実施計画: auth-engine JWT / JWKS 契約整理

> 作成日: 2026-07-04
> ステータス: 着手前
> 出典: [fable-specific-weaknesses.md](../../../engine/docs/evaluation/fable-specific-weaknesses.md)

---

## 1. 目的

- `auth` が発行する JWT を `engine` が検証できる前提を整える。
- claim、`iss` / `aud` / `kid`、JWKS 公開、失効モデルを文書化し、後続実装の契約面を先に固定する。

---

## 2. 対象

- `auth/lib/auth/token/keys.ex`
- `auth/lib/auth/token.ex`
- `auth/config/config.exs`
- `auth/config/runtime.exs`
- `auth/README.md` または `auth/.workspace/` 配下の設計メモ

---

## 3. この計画で決めること

- JWT の必須 claim
- `engine` が検証時に見るべき項目
- `kid` の付与規則
- JWKS の複数鍵併存方針
- logout / revoke / key rotation と resource server 側検証の関係

---

## 4. タスク

- [ ] 現行 JWT の claim と不足項目を棚卸しする
- [ ] `engine` 向けの検証契約を 1 枚のメモにまとめる
- [ ] `kid` 前提の鍵表現へ拡張する設計を決める
- [ ] JWKS を単一鍵固定から複数鍵併存可能な形へ設計する
- [ ] access token 短命化と外部検証の関係を明記する

---

## 5. 非目標

- `engine` 側の実装そのもの
- RoomToken や UDP / Zenoh 認証の最終仕様確定

---

## 6. 受け入れ条件

- [ ] JWT / JWKS 契約が文書として参照可能
- [ ] `iss` / `aud` / `kid` の方針が決まっている
- [ ] 鍵ローテーション時に旧トークン検証を継続できる前提が整理されている
