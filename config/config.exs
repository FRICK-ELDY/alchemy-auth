# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :auth,
  ecto_repos: [Auth.Repo],
  ash_domains: [Auth.Domain],
  generators: [timestamp_type: :utc_datetime],
  jwt_issuer: "alchemy-auth",
  jwt_audience: "alchemy-platform",
  jwt_ttl_seconds: 86_400,
  jwt_private_key_path: "priv/jwt_private.pem",
  jwt_generate_key_on_startup: true

# Configure the endpoint
config :auth, AuthWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [json: AuthWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Auth.PubSub,
  live_view: [signing_salt: "PiklzKln"]

# Configure the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :auth, Auth.Mailer, adapter: Swoosh.Adapters.Local

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
