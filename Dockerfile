
ARG RUST_VERSION=1.77
ARG APP_NAME=server


FROM rust:${RUST_VERSION}-slim-bullseye AS build
ARG APP_NAME
WORKDIR /app

RUN --mount=type=bind,source=client/src,target=client/src \
    --mount=type=bind,source=client/Cargo.toml,target=client/Cargo.toml \
    --mount=type=bind,source=server/src,target=server/src \
    --mount=type=bind,source=server/Cargo.toml,target=server/Cargo.toml \
    --mount=type=bind,source=common/src,target=common/src \
    --mount=type=bind,source=common/Cargo.toml,target=common/Cargo.toml \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && \
    cp ./target/release/$APP_NAME /bin/server

FROM debian:bullseye-slim AS final

USER root

COPY --from=build /bin/server /bin/

EXPOSE 9876

CMD ["/bin/server", "0.0.0.0:9876"]
