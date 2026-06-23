defmodule Auth.Domain do
  @moduledoc """
  Ash domain for alchemy-auth user identity and token revocation.
  """

  use Ash.Domain

  resources do
    resource Auth.Accounts.User
    resource Auth.Accounts.TokenRevocation
  end
end
