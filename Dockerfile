# Exact Online MCP server - streamable HTTP transport for remote clients
# such as Microsoft Copilot Studio.
#
# In this mode the server is a pure bridge: the calling client does the OAuth2
# flow against Exact Online itself and sends the access token on every request.
# Nothing is stored, so this image needs no client id, no client secret and no
# volume.
#
# Build and deploy in one step (no local Docker needed):
#   az containerapp up --name exactonline-mcp --resource-group <rg> \
#     --location westeurope --environment exactonline-env --source .

FROM python:3.11-slim

# uv, copied from its official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Dependencies first: this layer is cached as long as uv.lock does not change,
# so code edits rebuild in seconds instead of minutes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Then the project itself. README.md is referenced by pyproject.toml, so the
# build backend needs it.
COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

# Run as a non-root user.
RUN useradd --create-home --uid 10001 app && chown -R app:app /app
USER app

ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080 \
    EXACT_ONLINE_REGION=nl

# Container Apps reads this to set the ingress target port.
EXPOSE 8080

CMD ["python", "-m", "exactonline_mcp"]
