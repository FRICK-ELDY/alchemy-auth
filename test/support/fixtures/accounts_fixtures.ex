defmodule Auth.AccountsFixtures do
  @moduledoc """
  Test helpers for creating `Auth.Accounts` entities.
  """

  @default_password "Password1"

  def default_password, do: @default_password

  def valid_register_attrs(overrides \\ %{}) do
    unique = System.unique_integer([:positive])

    Map.merge(
      %{
        username: "user#{unique}",
        email: "user#{unique}@example.com",
        password: @default_password,
        birthday: ~D[2000-01-31],
        promo_code: nil,
        tos_agreed: true
      },
      overrides
    )
  end

  def user_fixture(overrides \\ %{}) do
    {:ok, user} = Auth.Accounts.register(valid_register_attrs(overrides))
    user
  end
end
