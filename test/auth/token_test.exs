defmodule Auth.TokenTest do
  use Auth.DataCase, async: true

  alias Auth.Accounts
  alias Auth.Token

  setup do
    {:ok, user} = Accounts.register("token@example.com", "password123")
    %{user: user}
  end

  test "generates and verifies a token", %{user: user} do
    assert {:ok, token, _jti, 86_400} = Token.generate(user)
    assert {:ok, claims} = Token.verify(token)
    assert claims["sub"] == user.id
    assert claims["status"] == "active"
    assert claims["iss"] == "alchemy-auth"
    assert claims["aud"] == "alchemy-platform"
    assert is_binary(claims["jti"])
  end

  test "rejects revoked token", %{user: user} do
    assert {:ok, token, jti, _expires_in} = Token.generate(user)
    expires_at = DateTime.utc_now() |> DateTime.add(86_400, :second)

    assert {:ok, _} = Accounts.logout(jti, user.id, expires_at)
    assert {:error, :revoked} = Token.verify(token)
  end
end
