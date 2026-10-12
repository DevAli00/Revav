FROM python:3.12-slim AS base

LABEL maintainer="Ali <alielboury2@gmail.com>"
LABEL description="Revav — security product reverse engineering framework"

# System dependencies for binary analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/revav

# Install Python package
COPY pyproject.toml README.md LICENSE ./
COPY revav/ revav/
RUN pip install --no-cache-dir -e .

# Copy project files
COPY baselines/ baselines/
COPY templates/ templates/

# Create KB directory
RUN mkdir -p kb/profiles kb/catalog kb/layers kb/diffs

# Default working directory for analysis targets
RUN mkdir -p /targets
VOLUME ["/targets", "/opt/revav/kb"]

ENTRYPOINT ["revav"]
CMD ["--help"]
