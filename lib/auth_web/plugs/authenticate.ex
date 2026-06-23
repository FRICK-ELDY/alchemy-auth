defmodule AuthWeb.Plugs.Authenticate do
  @moduledoc """
  Verifies Bearer JWT and assigns `current_user_id` and `token_claims`.
  """

  import Plug.Conn
  import Phoenix.Controller

  alias Auth.Token

  def init(opts), do: opts

  def call(conn, _opts) do
    with {:ok, token} <- fetch_bearer_token(conn),
         {:ok, claims} <- Token.verify(token) do
      conn
      |> assign(:current_user_id, claims["sub"])
      |> assign(:token_claims, claims)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> put_view(json: AuthWeb.ErrorJSON)
        |> render(:"401")
        |> halt()
    end
  end

  defp fetch_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when byte_size(token) > 0 -> {:ok, token}
      _ -> {:error, :missing_token}
    end
  end
end
