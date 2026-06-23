defmodule AuthWeb.HealthController do
  use AuthWeb, :controller

  def index(conn, _params) do
    json(conn, %{status: "ok"})
  end
end
