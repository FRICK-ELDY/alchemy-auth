# Development image for alchemy-auth (hot reload via bind mount).
FROM elixir:1.19-alpine AS dev

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

# Production release build.
FROM elixir:1.19-alpine AS build

RUN apk add --no-cache build-base git

WORKDIR /app

RUN mix local.hex --force && mix local.rebar --force

ENV MIX_ENV=prod

COPY mix.exs mix.lock ./
RUN mix deps.get --only prod

COPY config config
COPY lib lib
COPY priv priv
COPY .formatter.exs ./

RUN mix compile
RUN mix release

# Production runtime (mix release).
FROM alpine:3.21 AS release

RUN apk add --no-cache libstdc++ openssl ncurses-libs ca-certificates

WORKDIR /app

RUN adduser -D -h /app auth
USER auth

COPY --from=build --chown=auth:auth /app/_build/prod/rel/auth ./

ENV PHX_SERVER=true
ENV PORT=4002

EXPOSE 4002

CMD ["bin/auth", "start"]
