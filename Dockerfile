# Forensic MCP server — Linux runtime used from a Windows host (Docker Desktop).
# Contains: Python 3.12 venv (/opt/venv) with volatility3 + mcp, .NET 9 runtime,
# the 17 Eric Zimmerman CLI tools (.NET 9 builds) and the Volatility 2.6 standalone binary.
# Project code is NOT copied: it is bind-mounted at /app by docker-compose.yml.
#
# Pinning (P7 hardening, L2 §12 point 4, 03/10/2026): base image by digest; every Python
# package by version (requirements.lock = pip freeze of the validated image); .NET runtime by
# version; forensic apt packages by version; every downloaded file checked against a SHA-256
# recorded on 03/10/2026 (trust on first use: the EZ download URLs are not versioned, so a new
# EZ release makes the build FAIL on purpose instead of silently changing the tools).
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1

# System packages: libicu for .NET, unzip/curl for the tool downloads, procps for ps/kill.
# Not pinned on purpose: Debian security updates replace these versions in the archive
# (a pin would break the build); the base image digest fixes the starting point.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip libicu72 procps \
 && rm -rf /var/lib/apt/lists/*

# Python environment: exact versions of every package (requirements.lock).
COPY requirements.lock /tmp/requirements.lock
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "pip==26.2.1" \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.lock \
 && rm /tmp/requirements.lock

# Unprivileged user: the forensic tools never run as root.
RUN useradd --create-home --uid 1000 --shell /bin/bash analyst \
 && mkdir -p /app /evidence /output \
 && chown analyst:analyst /app /output
USER analyst
ENV HOME=/home/analyst \
    DOTNET_ROOT=/home/analyst/.dotnet \
    PATH=/opt/venv/bin:/home/analyst/.dotnet:$PATH
WORKDIR /home/analyst

# .NET 9 runtime (official install script, script hash and runtime version pinned).
ARG DOTNET_INSTALL_SHA256=082f7685e156738a1b2e2ed8381a621870d4ce8e8c59278034556f05c186eb2e
ARG DOTNET_RUNTIME_VERSION=9.0.20
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
 && echo "$DOTNET_INSTALL_SHA256  /tmp/dotnet-install.sh" | sha256sum -c - \
 && bash /tmp/dotnet-install.sh --version "$DOTNET_RUNTIME_VERSION" --runtime dotnet \
        --install-dir "$HOME/.dotnet" \
 && rm /tmp/dotnet-install.sh \
 && dotnet --list-runtimes

# Eric Zimmerman CLI tools, .NET 9 builds, one folder per tool; each zip checked (SHA-256).
COPY --chown=analyst:analyst rules/ez_zips.sha256 /tmp/ez_zips.sha256
RUN set -e; mkdir -p "$HOME/forensic-tools/ez"; cd "$HOME/forensic-tools/ez"; \
    tr -d '\r' < /tmp/ez_zips.sha256 | while read -r sum t; do \
      curl -fsSL "https://download.ericzimmermanstools.com/net9/$t.zip" -o "$t.zip"; \
      echo "$sum  $t.zip" | sha256sum -c - \
        || { echo "EZ $t.zip changed upstream: review the release, update rules/ez_zips.sha256"; exit 1; }; \
      unzip -q "$t.zip" -d "$t"; rm "$t.zip"; \
    done; \
    test "$(ls -d */ | wc -l)" -eq 17; \
    rm /tmp/ez_zips.sha256; \
    dotnet "$(find EvtxECmd -name EvtxECmd.dll | head -1)" --sync

# Volatility 2.6 standalone (legacy images/profiles only), zip checked (SHA-256).
ARG VOL2_SHA256=dc375a0f6909cb93ac17a10e28a0963fcd2decfc3c4291aadb7e5e0cbe28874a
RUN cd "$HOME/forensic-tools" \
 && curl -fsSL https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip -o vol2.zip \
 && echo "$VOL2_SHA256  vol2.zip" | sha256sum -c - \
 && unzip -q vol2.zip && rm vol2.zip \
 && chmod +x volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone

# Volatility 3 downloads Windows symbols here on first use (persisted by a named volume).
RUN mkdir -p "$HOME/.cache/volatility3/symbols"

# Task 4.3c (approved 02/10/2026): disk images read as files, no mount (cap_drop ALL, no FUSE).
# The Sleuth Kit (mmls, fls, icat; built with libewf2 -> E01) and ewf-tools (ewfinfo, ewfverify).
# Versions pinned to the bookworm amd64 binaries (binNMU "+b1", not the source version shown on
# packages.debian.org).
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends sleuthkit=4.11.1+dfsg-1+b1 ewf-tools=20140813-1+b1 \
 && rm -rf /var/lib/apt/lists/*
USER analyst

WORKDIR /app
ENV PYTHONPATH=/app/src \
    FORENSIC_MCP_CONFIG=/app/forensic-mcp.docker.toml

# Dev mode: stay up so commands can be run with `docker compose exec forensic ...`.
CMD ["sleep", "infinity"]
