defmodule Auth.RateLimit do
  @moduledoc """
  ETS-backed fixed-window rate limiter for auth API endpoints.
  """

  use GenServer

  require Logger

  @table :auth_rate_limit
  @cleanup_interval_ms 5 * 60_000

  @type limit_config :: %{limit: pos_integer(), period_ms: pos_integer()}

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec hit(atom(), String.t(), limit_config()) :: :ok | {:error, :rate_limited}
  def hit(bucket, key, %{limit: limit, period_ms: period_ms})
      when is_atom(bucket) and is_binary(key) and is_integer(limit) and is_integer(period_ms) do
    if enabled?() do
      do_hit(bucket, key, limit, period_ms)
    else
      :ok
    end
  end

  @doc false
  def reset do
    if table_exists?() do
      :ets.delete_all_objects(@table)
    end

    :ok
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :public, :set, write_concurrency: true, read_concurrency: true])
    schedule_cleanup()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_stale_windows()
    schedule_cleanup()
    {:noreply, state}
  end

  defp do_hit(bucket, key, limit, period_ms) do
    window = div(System.system_time(:millisecond), period_ms)
    ets_key = {bucket, key, window}

    count = :ets.update_counter(@table, ets_key, {2, 1}, {ets_key, 0})

    if count > limit do
      emit_throttle(bucket)
      {:error, :rate_limited}
    else
      :ok
    end
  end

  defp emit_throttle(bucket) do
    {action, axis} = bucket_parts(bucket)

    :telemetry.execute(
      [:auth, :rate_limit, :throttle],
      %{count: 1},
      %{action: action, axis: axis, bucket: bucket}
    )

    Logger.warning(
      inspect(%{
        event: "auth.rate_limit.throttle",
        action: action,
        axis: axis,
        bucket: bucket
      })
    )
  end

  defp bucket_parts(bucket) do
    case bucket do
      :login_ip -> {:login, :ip}
      :login_identifier -> {:login, :identifier}
      :register_ip -> {:register, :ip}
      :register_email -> {:register, :email}
      :refresh_ip -> {:refresh, :ip}
      :refresh_token -> {:refresh, :token}
      other -> {:unknown, other}
    end
  end

  defp enabled? do
    Application.get_env(:auth, __MODULE__, [])
    |> Keyword.get(:enabled, true)
  end

  defp table_exists? do
    :ets.whereis(@table) != :undefined
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  defp cleanup_stale_windows do
    if table_exists?() do
      min_period_ms = min_period_ms()

      if min_period_ms > 0 do
        cutoff_window = div(System.system_time(:millisecond), min_period_ms) - 2

        :ets.select_delete(@table, [
          {{:"$1", :_, :"$2"}, [{:<, :"$2", cutoff_window}], [true]}
        ])
      end
    end
  end

  defp min_period_ms do
    Application.get_env(:auth, __MODULE__, [])
    |> Keyword.get(:limits, %{})
    |> Map.values()
    |> Enum.flat_map(&Map.values/1)
    |> Enum.map(&Map.get(&1, :period_ms, 0))
    |> Enum.min(fn -> 0 end)
  end
end
