# Use the official Rust image as a base
FROM rust:1.78 as builder

# Create a new empty shell project
WORKDIR /usr/src/hash-sig

# Copy over your manifests
COPY Cargo.toml Cargo.lock ./

# Copy over your source code
COPY src ./src

# Build the binary
# We specify the binary name here, which is the name of the package
RUN cargo build --release --bin keygen

# Use a minimal image for the final container
FROM debian:bullseye-slim

# Copy the built binary from the builder stage
COPY --from=builder /usr/src/hash-sig/target/release/keygen /usr/local/bin/keygen

# Set the binary as the entrypoint
ENTRYPOINT ["keygen"]
