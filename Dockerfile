# Forensic MCP server — Linux runtime used from a Windows host (Docker Desktop).
# Contains: Python 3.12 venv (/opt/venv) with volatility3 + mcp, .NET 9 runtime,
# the 17 Eric Zimmerman CLI tools (.NET 9 builds) and the Volatility 2.6 standalone binary.
# Project code is NOT copied: it is bind-mounted at /app by docker-compose.yml.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1

# System packages: libicu for .NET, unzip/curl for the tool downloads, procps for ps/kill.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip libicu72 procps \
 && rm -rf /var/lib/apt/lists/*

# Python environment (versions pinned for a reproducible deliverable).
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir \
        "mcp==2.2.0" "volatility3==2.28.2" \
        uvicorn pyyaml pytest \
        pycryptodome pefile capstone

# Unprivileged user: the forensic tools never run as root.
RUN useradd --create-home --uid 1000 --shell /bin/bash analyst \
 && mkdir -p /app /evidence /output \
 && chown analyst:analyst /app /output
USER analyst
ENV HOME=/home/analyst \
    DOTNET_ROOT=/home/analyst/.dotnet \
    PATH=/opt/venv/bin:/home/analyst/.dotnet:$PATH
WORKDIR /home/analyst

# .NET 9 runtime (official install script).
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
 && bash /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir "$HOME/.dotnet" \
 && rm /tmp/dotnet-install.sh \
 && dotnet --list-runtimes

# Eric Zimmerman CLI tools, .NET 9 builds, one folder per tool.
ARG EZ_TOOLS="EvtxECmd MFTECmd PECmd RECmd AmcacheParser AppCompatCacheParser LECmd JLECmd SBECmd SrumECmd SQLECmd WxTCmd RBCmd RecentFileCacheParser SumECmd bstrings rla"
RUN set -e; mkdir -p "$HOME/forensic-tools/ez"; cd "$HOME/forensic-tools/ez"; \
    for t in $EZ_TOOLS; do \
      curl -fsSL "https://download.ericzimmermanstools.com/net9/$t.zip" -o "$t.zip"; \
      unzip -q "$t.zip" -d "$t"; rm "$t.zip"; \
    done; \
    dotnet "$(find EvtxECmd -name EvtxECmd.dll | head -1)" --sync

# Volatility 2.6 standalone (legacy images/profiles only).
RUN cd "$HOME/forensic-tools" \
 && curl -fsSL https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip -o vol2.zip \
 && unzip -q vol2.zip && rm vol2.zip \
 && chmod +x volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone

# Volatility 3 downloads Windows symbols here on first use (persisted by a named volume).
RUN mkdir -p "$HOME/.cache/volatility3/symbols"

WORKDIR /app
ENV PYTHONPATH=/app/src \
    FORENSIC_MCP_CONFIG=/app/forensic-mcp.docker.toml

# Dev mode: stay up so commands can be run with `docker compose exec forensic ...`.
# Phase 7 replaces this with the HTTP server.
CMD ["sleep", "infinity"]
