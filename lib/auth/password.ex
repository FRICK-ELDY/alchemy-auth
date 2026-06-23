defmodule Auth.Password do
  @moduledoc """
  Password hashing for user credentials (PBKDF2-SHA512 via OTP `:crypto`).

  Production CI on Linux will switch to Argon2 per project design.
  """

  @iterations 100_000
  @derived_length 64

  @doc """
  Returns a password hash suitable for storage in `users.password_hash`.
  """
  @spec hash(String.t()) :: String.t()
  def hash(password) when is_binary(password) do
    salt = :crypto.strong_rand_bytes(16)
    derived = :crypto.pbkdf2_hmac(:sha512, password, salt, @iterations, @derived_length)

    "$pbkdf2-sha512$#{@iterations}$#{Base.url_encode64(salt, padding: false)}$#{Base.url_encode64(derived, padding: false)}"
  end

  @doc """
  Verifies a plaintext password against a stored hash.
  """
  @spec verify(String.t(), String.t()) :: boolean()
  def verify(password, hash) when is_binary(password) and is_binary(hash) do
    with ["", "pbkdf2-sha512", iterations, salt_b64, derived_b64] <- String.split(hash, "$"),
         {iterations, ""} <- Integer.parse(iterations),
         salt when is_binary(salt) <- Base.url_decode64(salt_b64, padding: false),
         stored when is_binary(stored) <- Base.url_decode64(derived_b64, padding: false) do
      derived = :crypto.pbkdf2_hmac(:sha512, password, salt, iterations, byte_size(stored))
      Plug.Crypto.secure_compare(derived, stored)
    else
      _ -> false
    end
  end
end
