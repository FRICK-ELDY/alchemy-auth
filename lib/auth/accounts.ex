defmodule Auth.Accounts do
  @moduledoc """
  Authentication operations: register, login, logout.
  """

  alias Auth.Accounts.{TokenRevocation, User}
  alias Auth.{Password, Token}

  @invalid_credentials_message "Invalid email or password"

  @spec register(String.t(), String.t()) :: {:ok, User.t()} | {:error, Ash.Error.t()}
  def register(email, password) when is_binary(email) and is_binary(password) do
    User.register(%{email: email, password: password})
  end

  @spec login(String.t(), String.t()) ::
          {:ok, map()}
          | {:error, :invalid_credentials}
  def login(email, password) when is_binary(email) and is_binary(password) do
    with {:ok, user} <- User.get_by_email(email),
         true <- user.status == :active,
         true <- Password.verify(password, user.password_hash),
         {:ok, access_token, _jti, expires_in} <- Token.generate(user) do
      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: expires_in
       }}
    else
      _ -> {:error, :invalid_credentials}
    end
  end

  @spec logout(String.t(), String.t(), DateTime.t()) ::
          {:ok, TokenRevocation.t()} | {:error, Ash.Error.t()}
  def logout(jti, user_id, expires_at) do
    TokenRevocation.revoke(%{
      jti: jti,
      user_id: user_id,
      expires_at: expires_at
    })
  end

  @spec get_user!(Ecto.UUID.t()) :: User.t()
  def get_user!(id) do
    Ash.get!(User, id)
  end

  @spec invalid_credentials_message() :: String.t()
  def invalid_credentials_message, do: @invalid_credentials_message
end
