defmodule Auth.MailConfig do
  @moduledoc false

  @providers ~w(postmark sendgrid mailgun smtp)

  @spec configure!() :: :ok
  def configure! do
    provider =
      System.get_env("MAIL_PROVIDER", "postmark")
      |> String.downcase()

    if provider not in @providers do
      raise """
      MAIL_PROVIDER must be one of #{inspect(@providers)}, got: #{inspect(provider)}
      """
    end

    mail_from = mail_from!()
    Application.put_env(:auth, :mail_from, mail_from)

    case provider do
      "postmark" -> configure_postmark!(mail_from)
      "sendgrid" -> configure_sendgrid!(mail_from)
      "mailgun" -> configure_mailgun!(mail_from)
      "smtp" -> configure_smtp!(mail_from)
    end

    :ok
  end

  defp mail_from! do
    name = System.get_env("MAIL_FROM_NAME", "Alchemy Auth")
    address = System.get_env("MAIL_FROM_ADDRESS") || raise_missing_env("MAIL_FROM_ADDRESS")
    {name, address}
  end

  defp configure_postmark!(mail_from) do
    api_key = fetch_env!("POSTMARK_API_KEY")

    Application.put_env(:auth, Auth.Mailer,
      adapter: Swoosh.Adapters.Postmark,
      api_key: api_key,
      from: mail_from
    )
  end

  defp configure_sendgrid!(mail_from) do
    api_key = fetch_env!("SENDGRID_API_KEY")

    Application.put_env(:auth, Auth.Mailer,
      adapter: Swoosh.Adapters.Sendgrid,
      api_key: api_key,
      from: mail_from
    )
  end

  defp configure_mailgun!(mail_from) do
    api_key = fetch_env!("MAILGUN_API_KEY")
    domain = fetch_env!("MAILGUN_DOMAIN")

    Application.put_env(:auth, Auth.Mailer,
      adapter: Swoosh.Adapters.Mailgun,
      api_key: api_key,
      domain: domain,
      from: mail_from
    )
  end

  defp configure_smtp!(mail_from) do
    relay = fetch_env!("SMTP_RELAY_HOST")
    port = String.to_integer(System.get_env("SMTP_RELAY_PORT", "587"))
    username = System.get_env("SMTP_USERNAME")
    password = System.get_env("SMTP_PASSWORD")
    tls? = System.get_env("SMTP_TLS") in ~w(true 1)

    relay_opts =
      [
        relay: relay,
        port: port,
        tls: if(tls?, do: :always, else: :never),
        auth: if(username && password, do: :always, else: :never),
        username: username,
        password: password
      ]
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)

    Application.put_env(:auth, Auth.Mailer,
      adapter: Swoosh.Adapters.SMTP,
      relay_opts: relay_opts,
      from: mail_from
    )
  end

  defp fetch_env!(name) do
    System.get_env(name) || raise_missing_env(name)
  end

  defp raise_missing_env(name) do
    provider = System.get_env("MAIL_PROVIDER", "postmark")

    raise """
    environment variable #{name} is missing.
    For MAIL_PROVIDER=#{provider}, #{name} is required.
    """
  end
end
