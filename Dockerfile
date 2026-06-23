# Development image for alchemy-auth (hot reload via bind mount).
FROM elixir:1.19-alpine

RUN apk add --no-cache build-base git

WORKDIR /app

RUN mix local.hex --force && mix local.rebar --force

# Warm dependency cache when building the image (source is bind-mounted at runtime).
COPY mix.exs mix.lock ./
RUN mix deps.get

COPY config config
COPY lib lib
COPY priv priv
COPY test test
COPY .formatter.exs ./
COPY AGENTS.md ./

RUN mix compile

EXPOSE 4002

CMD ["mix", "phx.server"]
