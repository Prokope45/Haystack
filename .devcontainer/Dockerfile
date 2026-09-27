FROM mcr.microsoft.com/devcontainers/go:1.23-bookworm

# Clean up expired yarn repository key that causes apt-get update to fail,
# and ensure python3-pip and python3-venv are available for Python analysis.
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends python3-pip python3-venv \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
