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
    case User.get_by_email(email) do
      {:ok, user} ->
        pw_verified = Password.verify(password, user.password_hash)

        if pw_verified and user.status == :active do
          case Token.generate(user) do
            {:ok, access_token, _jti, expires_in} ->
              {:ok,
               %{
                 access_token: access_token,
                 token_type: "Bearer",
                 expires_in: expires_in
               }}

            _ ->
              {:error, :invalid_credentials}
          end
        else
          {:error, :invalid_credentials}
        end

      {:error, _} ->
        Password.no_user_verify()
        {:error, :invalid_credentials}
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
