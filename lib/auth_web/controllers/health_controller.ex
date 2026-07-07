defmodule AuthWeb.HealthController do
  use AuthWeb, :controller

  @service "alchemy-auth"

  def index(conn, _params) do
    json(conn, %{
      status: "ok",
      service: @service,
      version: app_version()
    })
  end

  defp app_version do
    Application.spec(:auth, :vsn) |> to_string()
  end
end
