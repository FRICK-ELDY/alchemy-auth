defmodule Auth.Password do
  @moduledoc """
  Password hashing for user credentials (Argon2id).
  """

  @doc """
  Returns a password hash suitable for storage in `users.password_hash`.
  """
  @spec hash(String.t()) :: String.t()
  def hash(password) when is_binary(password) do
    Argon2.hash_pwd_salt(password)
  end

  @doc """
  Verifies a plaintext password against a stored hash.
  """
  @spec verify(String.t(), String.t()) :: boolean()
  def verify(password, hash) when is_binary(password) and is_binary(hash) do
    Argon2.verify_pass(password, hash)
  rescue
    _ -> false
  end
end
