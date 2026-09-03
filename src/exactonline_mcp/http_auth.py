"""Bearer-token passthrough for the streamable HTTP transport.

When this server runs over stdio (the local Claude Desktop setup) it manages
its own Exact Online tokens through :mod:`exactonline_mcp.auth`, backed by the
system keyring or an encrypted file. Nothing about that changes.

When it runs over streamable HTTP for a remote client such as Microsoft
Copilot Studio, the client performs the OAuth2 flow against Exact Online
itself and sends the resulting access token on every request as an
``Authorization: Bearer <token>`` header. In that mode this server stores no
tokens at all: :class:`BearerTokenMiddleware` lifts the token off the incoming
request into a context variable, and
``ExactOnlineClient._ensure_authenticated`` reads it back out.

A context variable is used rather than a parameter so that the tool functions
in :mod:`exactonline_mcp.server` need no changes: the value is set per request
and is visible to everything running within that request, including tasks
spawned from it.

Note that this only works when FastMCP runs in stateless HTTP mode, where each
request's work is started from the request itself. ``__main__`` sets
``FASTMCP_STATELESS_HTTP`` accordingly.
"""

from __future__ import annotations

import contextvars
import logging
import os
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

#: Set this to ``passthrough`` to take the access token from the request
#: instead of from local storage. ``__main__`` sets it for the HTTP transport.
AUTH_MODE_ENV_VAR = "EXACT_ONLINE_AUTH_MODE"
PASSTHROUGH_MODE = "passthrough"

_bearer_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "exact_online_bearer_token", default=None
)


def passthrough_enabled() -> bool:
    """Return True when the access token should come from the request.

    Returns:
        True if ``EXACT_ONLINE_AUTH_MODE`` is set to ``passthrough``.
    """
    return os.getenv(AUTH_MODE_ENV_VAR, "").strip().lower() == PASSTHROUGH_MODE


def get_bearer_token() -> str | None:
    """Get the bearer token supplied with the current request.

    Returns:
        The access token, or None when there is no request in scope or the
        request carried no usable ``Authorization`` header.
    """
    return _bearer_token.get()


def set_bearer_token(token: str | None) -> contextvars.Token[str | None]:
    """Set the bearer token for the current context.

    Args:
        token: The access token, or None to clear it.

    Returns:
        A reset token for :meth:`contextvars.ContextVar.reset`.
    """
    return _bearer_token.set(token)


def extract_bearer_token(scope: dict[str, Any]) -> str | None:
    """Pull the bearer token out of an ASGI scope.

    Args:
        scope: The ASGI connection scope.

    Returns:
        The token from the ``Authorization`` header, or None if the header is
        absent, malformed, or uses a scheme other than Bearer.
    """
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() != b"authorization":
            continue
        try:
            value = raw_value.decode("latin-1").strip()
        except UnicodeDecodeError:
            logger.warning("Authorization header is not decodable")
            return None
        scheme, _, token = value.partition(" ")
        if scheme.lower() != "bearer":
            logger.warning("Authorization header uses unsupported scheme %r", scheme)
            return None
        token = token.strip()
        return token or None
    return None


class BearerTokenMiddleware:
    """ASGI middleware that exposes the request's bearer token to the tools.

    Deliberately written against the raw ASGI interface rather than Starlette's
    ``BaseHTTPMiddleware``: the latter runs the downstream app in a separate
    task with its own context, which would hide the token from the tool call.
    """

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        """Wrap an ASGI application.

        Args:
            app: The ASGI application to wrap.
        """
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Handle one ASGI event, binding the token for its duration."""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        token = extract_bearer_token(scope)
        if token is None:
            logger.debug("No bearer token on request to %s", scope.get("path"))

        reset_token = set_bearer_token(token)
        try:
            await self.app(scope, receive, send)
        finally:
            _bearer_token.reset(reset_token)
