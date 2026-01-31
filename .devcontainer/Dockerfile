FROM python:3.10

# Install git, curl, jq and other utilities
RUN apt-get update && apt-get install -y git curl jq && rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -fsSL https://go.dev/dl/go1.23.6.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Claude Code CLI
RUN curl -fsSL https://claude.ai/install.sh | bash

# Add uv and Claude Code to PATH
ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"

# Set working directory
WORKDIR /workspace
