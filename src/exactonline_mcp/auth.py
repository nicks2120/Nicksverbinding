"""OAuth2 authentication for Exact Online API.

This module handles the OAuth2 authorization code flow, token storage,
and automatic token refresh for the Exact Online API.
"""

import asyncio
import ipaddress
import json
import logging
import os
import secrets
import ssl
import webbrowser
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from exactonline_mcp.exceptions import AuthenticationError
from exactonline_mcp.models import Token

logger = logging.getLogger(__name__)

# Region-specific base URLs
REGION_URLS = {
    "nl": "https://start.exactonline.nl",
    "uk": "https://start.exactonline.co.uk",
}

DEFAULT_REDIRECT_URI = "https://localhost:8080/callback"


def get_base_url(region: str = "nl") -> str:
    """Get the base URL for a specific region.

    Args:
        region: Region code ('nl' or 'uk').

    Returns:
        Base URL for the region.

    Raises:
        ValueError: If region is not supported.
    """
    if region not in REGION_URLS:
        raise ValueError(f"Unsupported region: {region}. Use 'nl' or 'uk'.")
    return REGION_URLS[region]


class TokenStorage(ABC):
    """Abstract base class for secure token storage."""

    @abstractmethod
    async def load(self) -> Token | None:
        """Load stored token.

        Returns:
            Token if found, None otherwise.
        """
        pass

    @abstractmethod
    async def save(self, token: Token) -> None:
        """Save token to storage.

        Args:
            token: Token to save.
        """
        pass

    @abstractmethod
    async def delete(self) -> None:
        """Delete stored token."""
        pass


class KeyringStorage(TokenStorage):
    """Token storage using system keyring (macOS Keychain, etc.)."""

    SERVICE_NAME = "exactonline-mcp"
    ACCOUNT_NAME = "oauth_tokens"

    async def load(self) -> Token | None:
        """Load token from system keyring.

        Returns:
            Token if found and valid, None otherwise.
        """
        try:
            import keyring

            data = keyring.get_password(self.SERVICE_NAME, self.ACCOUNT_NAME)
            if data is None:
                return None

            token_dict = json.loads(data)
            return Token.from_dict(token_dict)
        except Exception as e:
            logger.debug(f"Failed to load from keyring: {e}")
            return None

    async def save(self, token: Token) -> None:
        """Save token to system keyring.

        Args:
            token: Token to save.
        """
        import keyring

        data = json.dumps(token.to_dict())
        keyring.set_password(self.SERVICE_NAME, self.ACCOUNT_NAME, data)
        logger.debug("Token saved to keyring")

    async def delete(self) -> None:
        """Delete token from system keyring."""
        try:
            import keyring

            keyring.delete_password(self.SERVICE_NAME, self.ACCOUNT_NAME)
            logger.debug("Token deleted from keyring")
        except Exception:
            pass  # Token may not exist


class EncryptedFileStorage(TokenStorage):
    """Fallback token storage using encrypted JSON file."""

    def __init__(self, storage_dir: Path | None = None) -> None:
        """Initialize encrypted file storage.

        Args:
            storage_dir: Directory for token files. Defaults to ~/.exactonline_mcp/
        """
        if storage_dir is None:
            storage_dir = Path.home() / ".exactonline_mcp"
        self.storage_dir = storage_dir
        self.token_file = storage_dir / "tokens.json.enc"
        self.key_file = storage_dir / "tokens.key"

    def _get_or_create_key(self) -> bytes:
        """Get existing encryption key or create a new one.

        Returns:
            Encryption key bytes.
        """
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        if self.key_file.exists():
            return self.key_file.read_bytes()

        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        # Set restrictive permissions
        self.key_file.chmod(0o600)
        return key

    async def load(self) -> Token | None:
        """Load token from encrypted file.

        Returns:
            Token if found and valid, None otherwise.
        """
        try:
            if not self.token_file.exists():
                return None

            key = self._get_or_create_key()
            cipher = Fernet(key)

            encrypted_data = self.token_file.read_bytes()
            decrypted_data = cipher.decrypt(encrypted_data)
            token_dict = json.loads(decrypted_data.decode())

            return Token.from_dict(token_dict)
        except Exception as e:
            logger.debug(f"Failed to load from encrypted file: {e}")
            return None

    async def save(self, token: Token) -> None:
        """Save token to encrypted file.

        Args:
            token: Token to save.
        """
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        key = self._get_or_create_key()
        cipher = Fernet(key)

        data = json.dumps(token.to_dict()).encode()
        encrypted_data = cipher.encrypt(data)

        self.token_file.write_bytes(encrypted_data)
        self.token_file.chmod(0o600)
        logger.debug("Token saved to encrypted file")

    async def delete(self) -> None:
        """Delete encrypted token file."""
        try:
            if self.token_file.exists():
                self.token_file.unlink()
            logger.debug("Token file deleted")
        except Exception:
            pass


def get_storage() -> TokenStorage:
    """Get the appropriate token storage backend.

    Tries keyring first, falls back to encrypted file storage.

    Returns:
        TokenStorage instance.
    """
    try:
        import keyring

        # Test if keyring is functional
        keyring.get_password("exactonline-mcp-test", "test")
        return EncryptedFileStorage()  # patch: Windows Credential Manager kan de tokens niet opslaan
    except Exception:
        logger.info("Keyring not available, using encrypted file storage")
        return EncryptedFileStorage()


def get_or_create_ssl_cert(storage_dir: Path | None = None) -> tuple[Path, Path]:
    """Get or create a self-signed SSL certificate for localhost.

    Args:
        storage_dir: Directory to store certificate files.

    Returns:
        Tuple of (cert_path, key_path).
    """
    if storage_dir is None:
        storage_dir = Path.home() / ".exactonline_mcp"
    storage_dir.mkdir(parents=True, exist_ok=True)

    cert_path = storage_dir / "localhost.crt"
    key_path = storage_dir / "localhost.key"

    # Return existing certificate if still valid
    if cert_path.exists() and key_path.exists():
        try:
            cert_data = cert_path.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data)
            if cert.not_valid_after_utc > datetime.now(cert.not_valid_after_utc.tzinfo):
                return cert_path, key_path
        except Exception:
            pass  # Regenerate if invalid

    # Generate new RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Generate self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "exactonline-mcp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(datetime.now() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Save key
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)

    # Save certificate
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Generated self-signed certificate at {cert_path}")
    return cert_path, key_path


class OAuth2Client:
    """OAuth2 client for Exact Online authentication."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        region: str = "nl",
        redirect_uri: str = DEFAULT_REDIRECT_URI,
    ) -> None:
        """Initialize OAuth2 client.

        Args:
            client_id: Exact Online OAuth2 client ID.
            client_secret: Exact Online OAuth2 client secret.
            region: Region code ('nl' or 'uk').
            redirect_uri: OAuth2 callback URL.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = get_base_url(region)
        self.redirect_uri = redirect_uri
        self.storage = get_storage()

    def get_authorization_url(self, state: str | None = None) -> tuple[str, str]:
        """Generate OAuth2 authorization URL.

        Args:
            state: Optional state parameter for CSRF protection.

        Returns:
            Tuple of (authorization_url, state).
        """
        if state is None:
            state = secrets.token_urlsafe(32)

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
        }

        url = f"{self.base_url}/api/oauth2/auth?{urlencode(params)}"
        return url, state

    async def exchange_code(self, code: str) -> Token:
        """Exchange authorization code for tokens.

        Args:
            code: Authorization code from OAuth2 callback.

        Returns:
            Token with access and refresh tokens.

        Raises:
            AuthenticationError: If token exchange fails.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/api/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )

            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.status_code}")
                raise AuthenticationError(
                    "Failed to exchange authorization code for tokens"
                )

            data = response.json()
            token = Token(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                obtained_at=datetime.now(),
                expires_in=data.get("expires_in", 600),
            )

            await self.storage.save(token)
            return token

    async def refresh_token(self, token: Token) -> Token:
        """Refresh an expired access token.

        Args:
            token: Current token with valid refresh_token.

        Returns:
            New Token with fresh access and refresh tokens.

        Raises:
            AuthenticationError: If refresh fails.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/api/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": token.refresh_token,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )

            if response.status_code != 200:
                logger.error(f"Token refresh failed: {response.status_code}")
                raise AuthenticationError(
                    "Failed to refresh token. Please re-authenticate."
                )

            data = response.json()
            new_token = Token(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                obtained_at=datetime.now(),
                expires_in=data.get("expires_in", 600),
            )

            # Important: Save immediately as old refresh token is now invalid
            await self.storage.save(new_token)
            return new_token

    async def get_valid_token(self) -> Token:
        """Get a valid access token, refreshing if necessary.

        Returns:
            Valid Token.

        Raises:
            AuthenticationError: If no valid token available.
        """
        token = await self.storage.load()

        if token is None:
            raise AuthenticationError()

        # Refresh if expired or about to expire (within 30 seconds)
        if token.is_expired(buffer_seconds=30):
            logger.debug("Token expired, refreshing...")
            token = await self.refresh_token(token)

        return token


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OAuth2 callback."""

    authorization_code: str | None = None
    state: str | None = None
    error: str | None = None

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress HTTP server logging."""
        pass

    def do_GET(self) -> None:
        """Handle GET request from OAuth2 callback."""
        parsed = urlparse(self.path)

        if parsed.path != "/callback":
            self.send_error(404)
            return

        params = parse_qs(parsed.query)

        if "error" in params:
            CallbackHandler.error = params["error"][0]
            self._send_response("Authentication failed. You can close this window.")
            return

        if "code" not in params:
            self._send_response("Missing authorization code. Please try again.")
            return

        CallbackHandler.authorization_code = params["code"][0]
        CallbackHandler.state = params.get("state", [None])[0]
        self._send_response(
            "Authentication successful! You can close this window and return to the terminal."
        )

    def _send_response(self, message: str) -> None:
        """Send HTML response to browser."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Exact Online Authentication</title></head>
        <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
            <h1>{message}</h1>
        </body>
        </html>
        """
        self.wfile.write(html.encode())


async def run_auth_flow() -> Token:
    """Run the interactive OAuth2 authentication flow.

    This function:
    1. Generates/loads a self-signed SSL certificate for localhost
    2. Starts a local HTTPS server for the callback
    3. Opens the browser to the Exact Online login page
    4. Waits for the user to authorize
    5. Exchanges the authorization code for tokens
    6. Stores the tokens securely

    Returns:
        Token with access and refresh tokens.

    Raises:
        AuthenticationError: If authentication fails.
        ValueError: If required environment variables are missing.
    """
    from dotenv import load_dotenv

    load_dotenv()

    client_id = os.getenv("EXACT_ONLINE_CLIENT_ID")
    client_secret = os.getenv("EXACT_ONLINE_CLIENT_SECRET")
    region = os.getenv("EXACT_ONLINE_REGION", "nl")
    redirect_uri = os.getenv("EXACT_ONLINE_REDIRECT_URI", DEFAULT_REDIRECT_URI)

    if not client_id or not client_secret:
        raise ValueError(
            "Missing EXACT_ONLINE_CLIENT_ID or EXACT_ONLINE_CLIENT_SECRET. "
            "Please set them in .env file."
        )

    oauth_client = OAuth2Client(client_id, client_secret, region, redirect_uri)

    # Reset handler state
    CallbackHandler.authorization_code = None
    CallbackHandler.state = None
    CallbackHandler.error = None

    # Determine if using external tunnel (ngrok, etc.) or localhost
    is_localhost = "localhost" in redirect_uri or "127.0.0.1" in redirect_uri

    # Start callback server
    server = HTTPServer(("localhost", 8080), CallbackHandler)

    if is_localhost and redirect_uri.startswith("https://"):
        # Local HTTPS with self-signed certificate
        cert_path, key_path = get_or_create_ssl_cert()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

    server_thread = Thread(target=server.handle_request, daemon=True)
    server_thread.start()

    # Open browser for authorization
    auth_url, expected_state = oauth_client.get_authorization_url()
    print("\nOpening browser for Exact Online authentication...")
    print(f"If the browser doesn't open, visit: {auth_url}")

    if is_localhost and redirect_uri.startswith("https://"):
        print("\nNote: Your browser may show a security warning for the self-signed")
        print("certificate. Click 'Advanced' and 'Proceed to localhost' to continue.")
    elif not is_localhost:
        print(f"\nUsing external callback: {redirect_uri}")
        print("Make sure your tunnel (e.g., ngrok http 8080) is running!")

    print("")
    webbrowser.open(auth_url)

    # Wait for callback
    print("Waiting for authorization...")
    server_thread.join(timeout=120)  # 2 minute timeout

    if CallbackHandler.error:
        raise AuthenticationError(f"OAuth2 error: {CallbackHandler.error}")

    if CallbackHandler.authorization_code is None:
        raise AuthenticationError("Authorization timeout or cancelled")

    if CallbackHandler.state != expected_state:
        raise AuthenticationError("State mismatch - possible CSRF attack")

    # Exchange code for tokens
    print("Exchanging authorization code for tokens...")
    token = await oauth_client.exchange_code(CallbackHandler.authorization_code)

    print("\nAuthentication successful!")
    print("Tokens have been stored securely.")
    return token


def main() -> None:
    """CLI entry point for authentication."""
    try:
        asyncio.run(run_auth_flow())
    except KeyboardInterrupt:
        print("\nAuthentication cancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
