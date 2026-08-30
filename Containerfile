# Two shared bases (D63): build fat, ship distroless. The build stage is
# discarded once the binary is copied out, so its size is not a runtime concern.
# `:latest` here is deliberate and is the point of having shared bases. Pinning a
# digest in every Containerfile would mean editing ~61 of them each time a base
# is rebuilt for a CVE — which is how bases stop being rebuilt. The base images
# are themselves built, scanned, signed and digest-pinned by the base-images
# workflow (D61, D63); this is where that indirection is spent.
#
# The ignore must sit IMMEDIATELY before the instruction — a comment in between
# and hadolint does not see it.
# hadolint ignore=DL3007
FROM ghcr.io/yadgarhq/rust-build:latest AS chef
WORKDIR /app

# cargo-chef splits dependency compilation from source compilation, so a
# source-only change does not rebuild the dependency graph.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
# musl, so the runtime can be distroless/static rather than distroless/cc — a
# base ten times larger carrying a libc nothing here calls (D63).
RUN cargo build --release --target x86_64-unknown-linux-musl

# hadolint ignore=DL3007
FROM ghcr.io/yadgarhq/runtime:latest
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/yadgar-iam-db /yadgar-iam-db

# The runtime base already declares this (D63). Repeating it is deliberate: a
# static scanner reads THIS file and cannot follow the base image, so without the
# line the image looks like it runs as root. Stating it also means a future change
# of base cannot silently drop the guarantee.
USER 65532:65532
EXPOSE 50051
ENTRYPOINT ["/yadgar-iam-db"]
