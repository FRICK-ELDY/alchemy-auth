defmodule Auth.AccountsTest do
  use Auth.DataCase, async: true

  alias Auth.Accounts
  alias Auth.Password
  alias Auth.Repo

  describe "register/2" do
    test "creates a user with hashed password" do
      assert {:ok, user} = Accounts.register("user@example.com", "password123")
      assert to_string(user.email) == "user@example.com"
      assert user.status == :active
      assert Password.verify("password123", user.password_hash)
    end

    test "rejects duplicate email" do
      assert {:ok, _} = Accounts.register("dup@example.com", "password123")
      assert {:error, %Ash.Error.Invalid{}} = Accounts.register("dup@example.com", "password456")
    end

    test "rejects short password" do
      assert {:error, %Ash.Error.Invalid{}} = Accounts.register("short@example.com", "short")
    end
  end

  describe "login/2" do
    setup do
      {:ok, user} = Accounts.register("login@example.com", "password123")
      %{user: user}
    end

    test "returns access token for valid credentials" do
      assert {:ok, %{access_token: token, token_type: "Bearer", expires_in: 86_400}} =
               Accounts.login("login@example.com", "password123")

      assert is_binary(token)
    end

    test "rejects invalid password" do
      assert {:error, :invalid_credentials} =
               Accounts.login("login@example.com", "wrong-password")
    end

    test "rejects unknown email" do
      assert {:error, :invalid_credentials} =
               Accounts.login("missing@example.com", "password123")
    end

    test "rejects suspended user", %{user: user} do
      Ecto.Adapters.SQL.query!(Repo, "UPDATE users SET status = $1 WHERE id = $2", [
        "suspended",
        Ecto.UUID.dump!(user.id)
      ])

      assert {:error, :invalid_credentials} =
               Accounts.login("login@example.com", "password123")
    end
  end
end
