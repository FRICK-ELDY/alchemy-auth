defmodule Auth.Token do
  @moduledoc """
  JWT access tokens (RS256) for alchemy-platform sessions.
  """

  alias Auth.Accounts.{TokenRevocation, User}
  alias Auth.Token.Keys

  @doc """
  Issues a signed access token for the given user.

  Returns `{:ok, token, jti, expires_in}`.
  """
  @spec generate(User.t()) :: {:ok, String.t(), String.t(), non_neg_integer()}
  def generate(%User{} = user) do
    jti = Ecto.UUID.generate()
    ttl = Application.fetch_env!(:auth, :jwt_ttl_seconds)

    extra_claims = %{
      "sub" => user.id,
      "status" => to_string(user.status),
      "jti" => jti
    }

    signer = Keys.signer()

    case Joken.generate_and_sign(token_config(), extra_claims, signer) do
      {:ok, token, _claims} -> {:ok, token, jti, ttl}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verifies a bearer token and returns claims when valid.
  """
  @spec verify(String.t()) :: {:ok, map()} | {:error, atom()}
  def verify(token) when is_binary(token) do
    signer = Keys.signer()

    with {:ok, claims} <- Joken.verify_and_validate(token_config(), token, signer),
         :ok <- ensure_not_revoked(claims["jti"]),
         :ok <- ensure_user_active(claims["sub"]) do
      {:ok, claims}
    else
      {:error, :revoked} -> {:error, :revoked}
      {:error, :unauthorized} -> {:error, :unauthorized}
      {:error, _reason} -> {:error, :invalid_token}
    end
  end

  defp token_config do
    ttl = Application.fetch_env!(:auth, :jwt_ttl_seconds)
    issuer = Application.fetch_env!(:auth, :jwt_issuer)
    audience = Application.fetch_env!(:auth, :jwt_audience)

    Joken.Config.default_claims(default_exp: ttl, iss: issuer, aud: audience)
    |> Joken.Config.add_claim("sub", fn -> nil end, &valid_uuid?/1)
    |> Joken.Config.add_claim("status", fn -> nil end, &valid_status?/1)
    |> Joken.Config.add_claim("jti", fn -> nil end, &valid_uuid?/1)
  end

  defp valid_uuid?(value) when is_binary(value) do
    match?({:ok, _}, Ecto.UUID.cast(value))
  end

  defp valid_uuid?(_), do: false

  defp valid_status?(value) when value in ["active", "suspended", "deleted"], do: true
  defp valid_status?(_), do: false

  defp ensure_not_revoked(jti) do
    case TokenRevocation.get_by_jti(jti) do
      {:ok, _} -> {:error, :revoked}
      {:error, error} -> if not_found?(error), do: :ok, else: {:error, error}
    end
  end

  defp not_found?(%Ash.Error.Query.NotFound{}), do: true

  defp not_found?(%Ash.Error.Invalid{errors: errors}) when is_list(errors) do
    Enum.any?(errors, &not_found?/1)
  end

  defp not_found?(_), do: false

  defp ensure_user_active(user_id) do
    case Ash.get(User, user_id) do
      {:ok, %{status: :active}} -> :ok
      _ -> {:error, :unauthorized}
    end
  end
end
