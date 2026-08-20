# Optional custom image. The live devcontainer uses
# mcr.microsoft.com/devcontainers/cpp:ubuntu-22.04 directly so Cursor
# does not pick up the production Dockerfile at the repo root.
FROM mcr.microsoft.com/devcontainers/cpp:ubuntu-22.04

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
