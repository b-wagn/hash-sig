FROM rustlang/rust:nightly AS builder

WORKDIR /usr/src/hash-sig

# Copy manifests first to leverage caching
COPY Cargo.toml Cargo.lock ./

# Copy actual source code
COPY src ./src

# Build only the keygen binary
RUN cargo build --release --bin keygen

FROM ubuntu:22.04

COPY --from=builder /usr/src/hash-sig/target/release/keygen /usr/local/bin/keygen

ENTRYPOINT ["keygen"]

