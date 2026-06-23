defmodule AuthWeb.AuthController do
  use AuthWeb, :controller

  alias Auth.Accounts

  def register(conn, %{"email" => email, "password" => password}) do
    case Accounts.register(email, password) do
      {:ok, user} ->
        conn
        |> put_status(:created)
        |> json(%{user_id: user.id, email: to_string(user.email)})

      {:error, %Ash.Error.Invalid{} = error} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: %{detail: register_error_message(error)}})
    end
  end

  def register(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{errors: %{detail: "email and password are required"}})
  end

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.login(email, password) do
      {:ok, tokens} ->
        json(conn, tokens)

      {:error, :invalid_credentials} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{errors: %{detail: Accounts.invalid_credentials_message()}})

      {:error, _other} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{errors: %{detail: "An unexpected error occurred"}})
    end
  end

  def login(conn, _params) do
    conn
    |> put_status(:unauthorized)
    |> json(%{errors: %{detail: Accounts.invalid_credentials_message()}})
  end

  def logout(conn, _params) do
    claims = conn.assigns.token_claims
    expires_at = DateTime.from_unix!(claims["exp"])

    case Accounts.logout(claims["jti"], claims["sub"], expires_at) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, _error} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: %{detail: "could not revoke token"}})
    end
  end

  def me(conn, _params) do
    user = conn.assigns.current_user

    json(conn, %{
      user_id: user.id,
      email: to_string(user.email),
      status: to_string(user.status)
    })
  end

  defp register_error_message(%Ash.Error.Invalid{errors: errors}) do
    if email_taken?(errors) do
      "email has already been taken"
    else
      "could not create user"
    end
  end

  defp email_taken?(errors) do
    Enum.any?(errors, fn
      %Ash.Error.Changes.InvalidAttribute{field: :email} ->
        true

      %Ash.Error.Query.NotFound{} ->
        false

      other when is_struct(other) ->
        case Map.get(other, :errors) do
          nil -> false
          nested when is_list(nested) -> email_taken?(nested)
          _ -> false
        end

      _ ->
        false
    end)
  end
end
