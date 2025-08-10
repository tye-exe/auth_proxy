FROM rust:1.89.0 AS builder

WORKDIR /auth_proxy
RUN cargo init . 

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# Build & cache dependencies
RUN cargo build --release
RUN rm -r src/*

# Copy source files
COPY ./migrations ./migrations
COPY ./pages ./pages
COPY ./src ./src

RUN rm ./target/release/deps/auth_proxy*

# Required for sqlx macros
COPY ./database.sqlite3 ./database.sqlite3
RUN DATABASE_URL=sqlite:database.sqlite3 cargo build --release

FROM debian:stable-slim
COPY --from=builder /auth_proxy/target/release/auth_proxy /auth_proxy/.
ENTRYPOINT ["./auth_proxy/auth_proxy"]
