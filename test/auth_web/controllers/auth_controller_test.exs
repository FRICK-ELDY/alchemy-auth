defmodule AuthWeb.AuthControllerTest do
  use AuthWeb.ConnCase, async: true

  alias Auth.Accounts

  describe "POST /api/v1/auth/register" do
    test "creates a user", %{conn: conn} do
      conn =
        post(conn, ~p"/api/v1/auth/register", %{
          "email" => "new@example.com",
          "password" => "password123"
        })

      assert %{"user_id" => user_id, "email" => "new@example.com"} = json_response(conn, 201)
      assert user_id
    end

    test "returns 422 for duplicate email", %{conn: conn} do
      assert {:ok, _} = Accounts.register("dup@example.com", "password123")

      conn =
        post(conn, ~p"/api/v1/auth/register", %{
          "email" => "dup@example.com",
          "password" => "password456"
        })

      assert %{"errors" => %{"detail" => "email has already been taken"}} =
               json_response(conn, 422)
    end
  end

  describe "POST /api/v1/auth/login" do
    setup do
      {:ok, _} = Accounts.register("api@example.com", "password123")
      :ok
    end

    test "returns bearer token", %{conn: conn} do
      conn =
        post(conn, ~p"/api/v1/auth/login", %{
          "email" => "api@example.com",
          "password" => "password123"
        })

      assert %{
               "access_token" => token,
               "token_type" => "Bearer",
               "expires_in" => 86_400
             } = json_response(conn, 200)

      assert is_binary(token)
    end

    test "returns same error for invalid credentials", %{conn: conn} do
      conn =
        post(conn, ~p"/api/v1/auth/login", %{
          "email" => "api@example.com",
          "password" => "wrong-password"
        })

      assert %{"errors" => %{"detail" => "Invalid email or password"}} = json_response(conn, 401)
    end
  end

  describe "authenticated routes" do
    setup %{conn: conn} do
      {:ok, _} = Accounts.register("me@example.com", "password123")

      conn =
        post(conn, ~p"/api/v1/auth/login", %{
          "email" => "me@example.com",
          "password" => "password123"
        })

      token = json_response(conn, 200)["access_token"]
      auth_conn = put_req_header(build_conn(), "authorization", "Bearer " <> token)

      %{auth_conn: auth_conn}
    end

    test "GET /api/v1/auth/me", %{auth_conn: conn} do
      conn = get(conn, ~p"/api/v1/auth/me")

      assert %{
               "user_id" => _,
               "email" => "me@example.com",
               "status" => "active"
             } = json_response(conn, 200)
    end

    test "POST /api/v1/auth/logout", %{auth_conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/logout", %{})
      assert response(conn, 204)
    end

    test "rejects missing bearer token", %{conn: _conn} do
      conn = get(build_conn(), ~p"/api/v1/auth/me")
      assert json_response(conn, 401)
    end
  end
end
