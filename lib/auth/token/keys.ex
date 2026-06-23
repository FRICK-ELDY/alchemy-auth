defmodule Auth.Token.Keys do
  @moduledoc """
  Loads or generates the RS256 signing key and exposes JWKS for verification.
  """

  use GenServer

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec signer() :: Joken.Signer.t()
  def signer, do: GenServer.call(__MODULE__, :signer)

  @spec jwks() :: map()
  def jwks, do: GenServer.call(__MODULE__, :jwks)

  @impl true
  def init(_opts) do
    path = Application.fetch_env!(:auth, :jwt_private_key_path)
    private_pem = load_or_generate_private_key!(path)
    signer = Joken.Signer.create("RS256", %{"pem" => private_pem})
    jwks = build_jwks(private_pem)

    {:ok, %{signer: signer, jwks: jwks}}
  end

  @impl true
  def handle_call(:signer, _from, state), do: {:reply, state.signer, state}

  @impl true
  def handle_call(:jwks, _from, state), do: {:reply, state.jwks, state}

  defp load_or_generate_private_key!(path) do
    if File.exists?(path) do
      File.read!(path)
    else
      generate_and_write_key_pair!(path)
    end
  end

  defp generate_and_write_key_pair!(private_path) do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    {_type, private_pem} = JOSE.JWK.to_pem(jwk)
    {_type, public_pem} = JOSE.JWK.to_pem(JOSE.JWK.to_public(jwk))

    public_path = String.replace(private_path, "private", "public")

    File.mkdir_p!(Path.dirname(private_path))
    File.write!(private_path, private_pem)
    File.write!(public_path, public_pem)

    private_pem
  end

  defp build_jwks(private_pem) do
    jwk = JOSE.JWK.from_pem(private_pem)
    public_jwk = JOSE.JWK.to_public(jwk)
    kid = thumbprint_kid(public_jwk)
    {_fields, jwk_map} = JOSE.JWK.to_map(public_jwk)

    %{
      "keys" => [
        jwk_map
        |> Map.put("kid", kid)
        |> Map.put("use", "sig")
        |> Map.put("alg", "RS256")
      ]
    }
  end

  defp thumbprint_kid(jwk) do
    case JOSE.JWK.thumbprint(jwk) do
      {:kid, kid} -> kid
      kid when is_binary(kid) -> kid
    end
  end
end
