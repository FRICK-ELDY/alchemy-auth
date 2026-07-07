defmodule Auth.Accounts do
  @moduledoc """
  Authentication operations: register, login, refresh, logout.
  """

  alias Auth.Accounts.{RefreshToken, TokenRevocation, User}
  alias Auth.{Password, Token}

  require Ash.Query
  import Ash.Expr

  @invalid_credentials_message "Invalid username/email or password"

  @typedoc """
  Session payload returned to clients after register/login/refresh.
  `:refresh_token` is only present when Remember Me is enabled.
  """
  @type session :: %{
          required(:access_token) => String.t(),
          required(:token_type) => String.t(),
          required(:expires_in) => non_neg_integer(),
          required(:user) => map(),
          optional(:refresh_token) => String.t()
        }

  @spec register(map()) :: {:ok, User.t()} | {:error, Ash.Error.t()}
  def register(attrs) when is_map(attrs) do
    User.register(attrs)
  end

  @doc """
  Logs in with a username or email. Identifiers containing `@` are treated
  as emails, otherwise as usernames (usernames cannot contain `@`).
  """
  @spec login(String.t(), String.t(), boolean()) ::
          {:ok, session()} | {:error, :invalid_credentials} | {:error, Ash.Error.t()}
  def login(identifier, password, remember_me? \\ false)
      when is_binary(identifier) and is_binary(password) do
    case get_by_identifier(identifier) do
      {:ok, user} ->
        pw_verified = Password.verify(password, user.password_hash)

        if pw_verified and user.status == :active do
          case issue_session(user, remember_me?) do
            {:ok, session} -> {:ok, session}
            _ -> {:error, :invalid_credentials}
          end
        else
          {:error, :invalid_credentials}
        end

      {:error, error} ->
        if Auth.AshErrors.not_found?(error) do
          Password.no_user_verify()
          {:error, :invalid_credentials}
        else
          {:error, error}
        end
    end
  end

  @doc """
  Issues an access token (and a refresh token when Remember Me is enabled)
  for an already-authenticated user.
  """
  @spec issue_session(User.t(), boolean()) :: {:ok, session()} | {:error, any()}
  def issue_session(%User{} = user, remember_me?) do
    with {:ok, access_token, _jti, expires_in} <- Token.generate(user) do
      session = %{
        access_token: access_token,
        token_type: "Bearer",
        expires_in: expires_in,
        user: user_payload(user)
      }

      if remember_me? do
        with {:ok, refresh_token} <- create_refresh_token(user) do
          {:ok, Map.put(session, :refresh_token, refresh_token)}
        end
      else
        {:ok, session}
      end
    end
  end

  @doc """
  Exchanges a refresh token for a new access token and a rotated refresh token.

  Each successful refresh revokes the presented token and issues a new one in the
  same token family. Reuse of a revoked token revokes the entire family.

  Tokens expire after `refresh_token_inactivity_days` of inactivity (sliding
  window on `last_used_at`).
  """
  @spec refresh(String.t()) :: {:ok, session()} | {:error, :invalid_refresh_token}
  def refresh(refresh_token) when is_binary(refresh_token) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    case get_refresh_token_record(refresh_token) do
      {:ok, %{revoked_at: revoked_at} = record} when not is_nil(revoked_at) ->
        revoke_refresh_token_family(record.family_id, now)
        {:error, :invalid_refresh_token}

      {:ok, record} ->
        do_refresh(record, now)

      _ ->
        {:error, :invalid_refresh_token}
    end
  end

  @doc """
  Revokes the current access token, and the given refresh token when provided
  (only if it belongs to the same user).
  """
  @spec logout(String.t(), String.t(), DateTime.t(), String.t() | nil) ::
          {:ok, TokenRevocation.t()} | {:error, Ash.Error.t()}
  def logout(jti, user_id, expires_at, refresh_token \\ nil) do
    if is_binary(refresh_token), do: revoke_refresh_token(refresh_token, user_id)

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

  @spec user_payload(User.t()) :: map()
  def user_payload(%User{} = user) do
    %{
      user_id: user.id,
      username: to_string(user.username),
      email: to_string(user.email)
    }
  end

  defp do_refresh(record, now) do
    with :ok <- ensure_refresh_token_usable(record, now),
         {:ok, %User{status: :active} = user} <- fetch_user(record.user_id),
         {:ok, new_refresh_token} <- rotate_refresh_token(record, user, now),
         {:ok, access_token, _jti, expires_in} <- Token.generate(user) do
      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: expires_in,
         refresh_token: new_refresh_token,
         user: user_payload(user)
       }}
    else
      _ -> {:error, :invalid_refresh_token}
    end
  end

  defp get_by_identifier(identifier) do
    if String.contains?(identifier, "@") do
      User.get_by_email(identifier)
    else
      User.get_by_username(identifier)
    end
  end

  defp create_refresh_token(user, family_id \\ nil) do
    plaintext = 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    family_id = family_id || Ecto.UUID.generate()

    case RefreshToken.create(%{
           user_id: user.id,
           family_id: family_id,
           token_hash: hash_refresh_token(plaintext),
           last_used_at: now
         }) do
      {:ok, _record} -> {:ok, plaintext}
      {:error, error} -> {:error, error}
    end
  end

  defp rotate_refresh_token(record, user, now) do
    with {:ok, _} <- RefreshToken.revoke(record, %{revoked_at: now}) do
      create_refresh_token(user, record.family_id)
    end
  end

  defp get_refresh_token_record(plaintext) do
    RefreshToken.get_by_token_hash(hash_refresh_token(plaintext))
  end

  defp ensure_refresh_token_usable(record, now) do
    inactivity_days = Application.fetch_env!(:auth, :refresh_token_inactivity_days)
    deadline = DateTime.add(record.last_used_at, inactivity_days * 86_400, :second)

    cond do
      not is_nil(record.revoked_at) -> {:error, :revoked}
      DateTime.compare(now, deadline) == :gt -> {:error, :expired}
      true -> :ok
    end
  end

  defp fetch_user(user_id) do
    Ash.get(User, user_id)
  end

  defp revoke_refresh_token_family(family_id, now) do
    RefreshToken
    |> Ash.Query.filter(expr(family_id == ^family_id and is_nil(revoked_at)))
    |> Ash.bulk_update(:revoke, %{revoked_at: now})

    :ok
  end

  defp revoke_refresh_token(plaintext, user_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    case get_refresh_token_record(plaintext) do
      {:ok, %{user_id: ^user_id, revoked_at: nil} = record} ->
        RefreshToken.revoke(record, %{revoked_at: now})

      _ ->
        :noop
    end
  end

  defp hash_refresh_token(plaintext) do
    :sha256
    |> :crypto.hash(plaintext)
    |> Base.encode16(case: :lower)
  end
end
