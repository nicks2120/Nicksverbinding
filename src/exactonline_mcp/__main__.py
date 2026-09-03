"""Entry point for running the Exact Online MCP server.

Two transports are supported, selected with the ``MCP_TRANSPORT`` environment
variable:

``stdio`` (default)
    For local clients such as Claude Desktop. The server manages its own
    Exact Online tokens through the system keyring or encrypted file storage.

``streamable-http``
    For remote clients such as Microsoft Copilot Studio. The client performs
    the OAuth2 flow against Exact Online itself and passes the access token
    through on every request; this server stores no tokens and needs no
    client secret.

Run locally:
    uv run python -m exactonline_mcp

Run over HTTP:
    MCP_TRANSPORT=streamable-http uv run python -m exactonline_mcp

The HTTP endpoint is served at ``/mcp`` on ``MCP_HOST``:``MCP_PORT``.
"""

import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - container/tunnel deployments need this
DEFAULT_PORT = 8080

_HTTP_TRANSPORT_ALIASES = frozenset(
    {"streamable-http", "streamable_http", "http"}
)


def _run_stdio() -> None:
    """Run the server over stdio using locally stored tokens."""
    from exactonline_mcp.server import mcp

    mcp.run()


def _run_http() -> None:
    """Run the server over streamable HTTP using per-request bearer tokens."""
    # FastMCP reads its settings from the environment when the server object is
    # constructed, so these must be set before exactonline_mcp.server is
    # imported.
    #
    # Stateless mode is required, not merely preferred: it starts each
    # request's work from the request itself, so the context variable holding
    # that request's bearer token is visible to the tool call. In stateful mode
    # the session runs in a long-lived task created during initialize, and the
    # token would not reach it.
    os.environ.setdefault("FASTMCP_STATELESS_HTTP", "true")
    os.environ.setdefault("EXACT_ONLINE_AUTH_MODE", "passthrough")

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise SystemExit(
            "uvicorn is required for the streamable HTTP transport. "
            "Run 'uv sync' to install it."
        ) from exc

    from exactonline_mcp.http_auth import BearerTokenMiddleware
    from exactonline_mcp.server import mcp

    app_factory = getattr(mcp, "streamable_http_app", None)
    if app_factory is None:  # pragma: no cover - depends on environment
        raise SystemExit(
            "The installed 'mcp' package does not provide the streamable HTTP "
            "transport. Run 'uv sync' to upgrade it."
        )

    host = os.getenv("MCP_HOST", DEFAULT_HOST)
    try:
        port = int(os.getenv("MCP_PORT", str(DEFAULT_PORT)))
    except ValueError as exc:
        raise SystemExit(
            f"MCP_PORT must be a number, got {os.environ['MCP_PORT']!r}"
        ) from exc

    app = BearerTokenMiddleware(app_factory())

    logger.info("Serving MCP over streamable HTTP at http://%s:%s/mcp", host, port)
    uvicorn.run(app, host=host, port=port)


def main() -> None:
    """Run the MCP server with the transport named by MCP_TRANSPORT."""
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()

    if transport in _HTTP_TRANSPORT_ALIASES:
        _run_http()
    elif transport == "stdio":
        _run_stdio()
    else:
        raise SystemExit(
            f"Unknown MCP_TRANSPORT {transport!r}. "
            "Use 'stdio' or 'streamable-http'."
        )


if __name__ == "__main__":
    main()
