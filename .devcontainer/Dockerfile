FROM python:3.10

# Install git and other utilities
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Claude Code CLI
RUN curl -fsSL https://claude.ai/install.sh | bash

# Add uv and Claude Code to PATH
ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"

# Set working directory
WORKDIR /workspace
