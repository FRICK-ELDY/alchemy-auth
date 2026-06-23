defmodule AuthWeb.HealthControllerTest do
  use AuthWeb.ConnCase, async: true

  test "GET /health", %{conn: conn} do
    conn = get(conn, ~p"/health")
    assert %{"status" => "ok"} = json_response(conn, 200)
  end
end
