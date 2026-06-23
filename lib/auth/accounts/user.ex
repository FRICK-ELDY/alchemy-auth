defmodule Auth.Accounts.User do
  @moduledoc """
  User identity resource. SSoT for alchemy-platform user accounts.
  """

  use Ash.Resource,
    otp_app: :auth,
    domain: Auth.Domain,
    data_layer: AshPostgres.DataLayer

  postgres do
    table "users"
    repo Auth.Repo
  end

  attributes do
    uuid_primary_key :id

    attribute :email, :ci_string do
      allow_nil? false
      public? true
    end

    attribute :password_hash, :string do
      allow_nil? false
      sensitive? true
    end

    attribute :status, :atom do
      constraints one_of: [:active, :suspended, :deleted]
      default :active
      allow_nil? false
      public? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_email, [:email]
  end

  actions do
    defaults [:read]

    read :get_by_email do
      get? true
      argument :email, :ci_string, allow_nil?: false
      filter expr(email == ^arg(:email))
    end

    create :register do
      accept [:email]
      argument :password, :string, allow_nil?: false, sensitive?: true

      validate present(:password) do
        message "is required"
      end

      validate string_length(:password, min: 8) do
        message "must be at least 8 characters"
      end

      change Auth.Accounts.Changes.HashPassword
    end

    update :set_status do
      accept [:status]
    end
  end

  code_interface do
    define :register, action: :register
    define :get_by_email, action: :get_by_email, args: [:email]
    define :set_status, action: :set_status
  end
end
