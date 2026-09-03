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
Set ``MCP_ALLOWED_HOSTS`` to the public domain to switch the SDK's Host
header check back on; see _configure_dns_rebinding_protection.
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

    _configure_dns_rebinding_protection(mcp)

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


def _configure_dns_rebinding_protection(mcp: object) -> None:
    """Set the MCP SDK's Host/Origin check to match where this server runs.

    The SDK turns DNS rebinding protection on automatically and, because the
    FastMCP server object is built with the default host of 127.0.0.1, it then
    allows localhost only. Behind a real domain every request comes back as
    421 Invalid Host header.

    MCP_ALLOWED_HOSTS holds a comma-separated list of host names to accept,
    for example "exactonline-mcp.example.northeurope.azurecontainerapps.io".
    Set it and only those hosts are served. Leave it empty and the check is
    switched off, which is the right call when a trusted ingress (Azure
    Container Apps, an application gateway) already terminates TLS and fixes
    the host.

    Args:
        mcp: The FastMCP server instance to configure.
    """
    try:
        from mcp.server.transport_security import TransportSecuritySettings
    except ImportError:  # pragma: no cover - older SDK without the check
        return

    raw = os.getenv("MCP_ALLOWED_HOSTS", "").strip()
    hosts = [h.strip() for h in raw.split(",") if h.strip()]

    if hosts:
        settings = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=hosts,
            allowed_origins=[f"https://{h}" for h in hosts],
        )
        logger.info("Host check on, accepting: %s", ", ".join(hosts))
    else:
        settings = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        logger.info(
            "Host check off. Set MCP_ALLOWED_HOSTS to your domain to switch it on."
        )

    mcp.settings.transport_security = settings


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
