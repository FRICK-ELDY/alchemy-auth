defmodule AuthWeb.AuthControllerTest do
  use AuthWeb.ConnCase, async: true

  import Auth.AccountsFixtures

  alias Auth.Accounts

  defp register_params(overrides) do
    %{
      "username" => "newuser",
      "email" => "new@example.com",
      "password" => default_password(),
      "birthday" => "2000-01-31",
      "tos_agreed" => true
    }
    |> Map.merge(overrides)
  end

  describe "POST /api/v1/auth/register" do
    test "creates a user and returns a session", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/register", register_params(%{}))

      assert %{
               "access_token" => token,
               "token_type" => "Bearer",
               "expires_in" => 86_400,
               "user" => %{
                 "user_id" => user_id,
                 "username" => "newuser",
                 "email" => "new@example.com"
               }
             } = json_response(conn, 201)

      assert is_binary(token)
      assert user_id
      refute Map.has_key?(json_response(conn, 201), "refresh_token")
    end

    test "returns a refresh token when remember_me is set", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/register", register_params(%{"remember_me" => true}))

      assert %{"refresh_token" => refresh_token} = json_response(conn, 201)
      assert is_binary(refresh_token)
    end

    test "returns 422 with field list for missing params", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/register", %{"email" => "only@example.com"})

      assert %{"errors" => %{"fields" => fields}} = json_response(conn, 422)
      assert Map.has_key?(fields, "username")
      assert Map.has_key?(fields, "password")
      assert Map.has_key?(fields, "birthday")
      assert Map.has_key?(fields, "tos_agreed")
    end

    test "returns 422 with field errors for duplicate email", %{conn: conn} do
      user_fixture(%{email: "dup@example.com"})

      conn =
        post(conn, ~p"/api/v1/auth/register", register_params(%{"email" => "dup@example.com"}))

      assert %{"errors" => %{"fields" => %{"email" => [_ | _]}}} = json_response(conn, 422)
    end

    test "returns 422 with field errors for weak password", %{conn: conn} do
      conn =
        post(conn, ~p"/api/v1/auth/register", register_params(%{"password" => "password1"}))

      assert %{"errors" => %{"fields" => %{"password" => messages}}} = json_response(conn, 422)
      assert Enum.any?(messages, &(&1 =~ "uppercase"))
    end

    test "returns 422 when TOS is not agreed", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/register", register_params(%{"tos_agreed" => false}))

      assert %{"errors" => %{"fields" => %{"tos_agreed" => [_ | _]}}} = json_response(conn, 422)
    end
  end

  describe "POST /api/v1/auth/login" do
    setup do
      user_fixture(%{username: "api_user", email: "api@example.com"})
      :ok
    end

    test "logs in with email identifier", %{conn: conn} do
      conn =
        post(conn, ~p"/api/v1/auth/login", %{
          "identifier" => "api@example.com",
          "password" => default_password()
        })

      assert %{
               "access_token" => token,
               "token_type" => "Bearer",
               "expires_in" => 86_400,
               "user" => %{"username" => "api_user"}
             } = json_response(conn, 200)

      assert is_binary(token)
    end

    test "logs in with username identifier and remember_me", %{conn: conn} do
      conn =
        post(conn, ~p"/api/v1/auth/login", %{
          "identifier" => "api_user",
          "password" => default_password(),
          "remember_me" => true
        })

      assert %{"refresh_token" => refresh_token} = json_response(conn, 200)
      assert is_binary(refresh_token)
    end

    test "returns same error for invalid credentials", %{conn: conn} do
      conn =
        post(conn, ~p"/api/v1/auth/login", %{
          "identifier" => "api@example.com",
          "password" => "Wrong-password1"
        })

      assert %{"errors" => %{"detail" => "Invalid username/email or password"}} =
               json_response(conn, 401)
    end
  end

  describe "POST /api/v1/auth/refresh" do
    setup do
      user = user_fixture()
      {:ok, session} = Accounts.issue_session(user, true)
      %{refresh_token: session.refresh_token}
    end

    test "returns a new access token", %{conn: conn, refresh_token: refresh_token} do
      conn = post(conn, ~p"/api/v1/auth/refresh", %{"refresh_token" => refresh_token})

      assert %{"access_token" => token, "refresh_token" => ^refresh_token} =
               json_response(conn, 200)

      assert is_binary(token)
    end

    test "returns 401 for an unknown token", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/refresh", %{"refresh_token" => "bogus"})
      assert json_response(conn, 401)
    end

    test "returns 401 when token is missing", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/refresh", %{})
      assert json_response(conn, 401)
    end
  end

  describe "authenticated routes" do
    setup %{conn: conn} do
      user_fixture(%{username: "me_user", email: "me@example.com"})

      conn =
        post(conn, ~p"/api/v1/auth/login", %{
          "identifier" => "me@example.com",
          "password" => default_password(),
          "remember_me" => true
        })

      body = json_response(conn, 200)
      auth_conn = put_req_header(build_conn(), "authorization", "Bearer " <> body["access_token"])

      %{auth_conn: auth_conn, refresh_token: body["refresh_token"]}
    end

    test "GET /api/v1/auth/me includes username", %{auth_conn: conn} do
      conn = get(conn, ~p"/api/v1/auth/me")

      assert %{
               "user_id" => _,
               "username" => "me_user",
               "email" => "me@example.com",
               "status" => "active"
             } = json_response(conn, 200)
    end

    test "POST /api/v1/auth/logout revokes the refresh token too", %{
      auth_conn: conn,
      refresh_token: refresh_token
    } do
      conn = post(conn, ~p"/api/v1/auth/logout", %{"refresh_token" => refresh_token})
      assert response(conn, 204)

      refresh_conn =
        post(build_conn(), ~p"/api/v1/auth/refresh", %{"refresh_token" => refresh_token})

      assert json_response(refresh_conn, 401)
    end

    test "rejects missing bearer token" do
      conn = get(build_conn(), ~p"/api/v1/auth/me")
      assert json_response(conn, 401)
    end
  end
end
