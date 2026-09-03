"""Exact Online API client with rate limiting and retry logic.

This module provides the ExactOnlineClient class for making authenticated
requests to the Exact Online REST API.
"""

import asyncio
import logging
import os
import re
import time
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv

from exactonline_mcp.auth import OAuth2Client, get_base_url
from exactonline_mcp.exceptions import (
    AuthenticationError,
    DivisionNotAccessibleError,
    EndpointNotFoundError,
    ExactOnlineError,
    NetworkError,
    RateLimitError,
)
from exactonline_mcp.http_auth import get_bearer_token, passthrough_enabled
from exactonline_mcp.models import (
    ACCOUNT_TYPE_CATEGORIES,
    AgingEntry,
    BalanceSheetCategory,
    BalanceSheetSummary,
    CustomerRevenue,
    Division,
    ExplorationResult,
    GLAccountBalance,
    OpenReceivable,
    ProfitLossOverview,
    ProjectRevenue,
    Token,
    TransactionLine,
)

logger = logging.getLogger(__name__)


def sanitize_odata_string(value: str) -> str:
    """Sanitize a string value for use in OData filter expressions.

    Prevents OData injection by escaping single quotes and validating input.

    Args:
        value: The string value to sanitize.

    Returns:
        Sanitized string safe for OData filter interpolation.

    Raises:
        ValueError: If the input contains suspicious patterns.
    """
    if not isinstance(value, str):
        raise ValueError("OData filter value must be a string")

    # Reject obviously malicious patterns
    suspicious_patterns = [
        " or ",
        " and ",
        " eq ",
        " ne ",
        " gt ",
        " lt ",
        " ge ",
        " le ",
    ]
    lower_value = value.lower()
    for pattern in suspicious_patterns:
        if pattern in lower_value:
            raise ValueError(f"Invalid characters in filter value: {value}")

    # Escape single quotes by doubling them (OData standard)
    return value.replace("'", "''")


def parse_odata_date(date_str: str | None) -> str | None:
    """Convert OData date format to ISO format string.

    Exact Online returns dates in OData format: /Date(milliseconds)/ or
    /Date(milliseconds+offset)/. This function extracts the timestamp
    and converts it to YYYY-MM-DD format.

    Args:
        date_str: OData date string (e.g., "/Date(1756684800000)/") or None.

    Returns:
        ISO format date string (e.g., "2025-09-01") or None if input is None.

    Examples:
        >>> parse_odata_date("/Date(1756684800000)/")
        "2025-09-01"
        >>> parse_odata_date(None)
        None
    """
    if date_str is None:
        return None

    # Match /Date(milliseconds)/ or /Date(milliseconds+offset)/
    match = re.match(r"/Date\((-?\d+)([+-]\d+)?\)/", date_str)
    if not match:
        # Return as-is if not OData format (might already be ISO)
        return date_str

    milliseconds = int(match.group(1))
    # Convert milliseconds to datetime
    dt = datetime.fromtimestamp(milliseconds / 1000)
    return dt.strftime("%Y-%m-%d")


class RateLimiter:
    """Rate limiter for Exact Online API (60 calls/minute)."""

    MAX_CALLS_PER_MINUTE = 60

    def __init__(self) -> None:
        """Initialize rate limiter."""
        self._call_times: list[float] = []
        self._lock = asyncio.Lock()

    async def wait_if_needed(self) -> None:
        """Wait if we're approaching the rate limit.

        This method tracks API calls within a sliding 60-second window
        and sleeps if necessary to stay under the limit.
        """
        async with self._lock:
            now = time.time()

            # Remove calls older than 60 seconds
            self._call_times = [t for t in self._call_times if now - t < 60]

            # If at limit, wait until oldest call expires
            if len(self._call_times) >= self.MAX_CALLS_PER_MINUTE:
                oldest = self._call_times[0]
                wait_time = 60 - (now - oldest) + 0.1  # Small buffer
                if wait_time > 0:
                    logger.debug(f"Rate limit reached, waiting {wait_time:.1f}s")
                    await asyncio.sleep(wait_time)
                    # Recheck after sleep
                    now = time.time()
                    self._call_times = [t for t in self._call_times if now - t < 60]

            # Record this call
            self._call_times.append(now)


class ExactOnlineClient:
    """Async HTTP client for Exact Online API.

    This client handles:
    - OAuth2 token management with automatic refresh
    - Rate limiting (60 calls/minute)
    - Retry logic with exponential backoff
    - Request timeout (30 seconds)
    """

    TIMEOUT = 30.0  # seconds
    MAX_RETRIES = 3
    RETRY_BACKOFF_BASE = 2  # seconds

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        region: str | None = None,
    ) -> None:
        """Initialize the Exact Online client.

        Args:
            client_id: OAuth2 client ID (or from EXACT_ONLINE_CLIENT_ID env var).
            client_secret: OAuth2 client secret (or from EXACT_ONLINE_CLIENT_SECRET env var).
            region: Region code 'nl' or 'uk' (or from EXACT_ONLINE_REGION env var).
        """
        load_dotenv()

        self.client_id = client_id or os.getenv("EXACT_ONLINE_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("EXACT_ONLINE_CLIENT_SECRET", "")
        self.region = region or os.getenv("EXACT_ONLINE_REGION", "nl")

        # In passthrough mode the calling MCP client owns the OAuth2 flow, so
        # this process needs no credentials of its own.
        self._passthrough = passthrough_enabled()

        if not self._passthrough and (not self.client_id or not self.client_secret):
            raise ValueError(
                "Missing EXACT_ONLINE_CLIENT_ID or EXACT_ONLINE_CLIENT_SECRET"
            )

        self.base_url = get_base_url(self.region)
        self.oauth_client = OAuth2Client(
            self.client_id, self.client_secret, self.region
        )
        self.rate_limiter = RateLimiter()
        self._http_client: httpx.AsyncClient | None = None
        self._current_token: Token | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client.

        Returns:
            Configured AsyncClient instance.
        """
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=self.TIMEOUT,
                limits=httpx.Limits(max_keepalive_connections=5),
            )
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _ensure_authenticated(self) -> str:
        """Ensure we have a valid access token.

        In passthrough mode the token arrives with the request and is returned
        as-is. It is deliberately not cached on this instance: the client is a
        process-wide singleton shared by every caller, so caching would leak
        one user's token to another.

        Returns:
            Valid access token.

        Raises:
            AuthenticationError: If authentication fails.
        """
        if self._passthrough:
            token = get_bearer_token()
            if not token:
                raise AuthenticationError(
                    message="No Exact Online access token was sent with this request",
                    action=(
                        "Connect this tool to your Exact Online account in the "
                        "MCP client so it sends an Authorization: Bearer header"
                    ),
                )
            return token

        # Get token from storage if not cached, or if expired
        if self._current_token is None or self._current_token.is_expired():
            self._current_token = await self.oauth_client.get_valid_token()

        return self._current_token.access_token

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an authenticated HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Full URL to request.
            **kwargs: Additional arguments for httpx.request.

        Returns:
            HTTP response.

        Raises:
            ExactOnlineError: On API errors.
            NetworkError: On connection errors.
        """
        client = await self._get_client()

        for attempt in range(self.MAX_RETRIES):
            try:
                # Ensure rate limit compliance
                await self.rate_limiter.wait_if_needed()

                # Get fresh token
                access_token = await self._ensure_authenticated()

                # Set authorization header
                headers = kwargs.pop("headers", {})
                headers["Authorization"] = f"Bearer {access_token}"
                headers["Accept"] = "application/json"

                # Make request
                response = await client.request(method, url, headers=headers, **kwargs)

                # Handle rate limit
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    if attempt < self.MAX_RETRIES - 1:
                        logger.warning(
                            f"Rate limited, waiting {retry_after}s (attempt {attempt + 1})"
                        )
                        await asyncio.sleep(retry_after)
                        continue
                    raise RateLimitError(retry_after=retry_after)

                # Handle auth errors
                if response.status_code == 401:
                    if self._passthrough:
                        # The token belongs to the calling client, so there is
                        # nothing to refresh here. Retrying would only repeat
                        # the same rejected token.
                        raise AuthenticationError(
                            message=(
                                "The Exact Online access token has expired or "
                                "was revoked"
                            ),
                            action=(
                                "Reconnect the Exact Online connection in your "
                                "MCP client and try again"
                            ),
                        )
                    # Token might have been revoked, clear and retry
                    self._current_token = None
                    if attempt < self.MAX_RETRIES - 1:
                        logger.warning("Auth error, refreshing token...")
                        continue
                    raise AuthenticationError()

                # Handle not found
                if response.status_code == 404:
                    raise EndpointNotFoundError(url.split("/api/v1/")[-1])

                # Handle forbidden (division access)
                if response.status_code == 403:
                    raise DivisionNotAccessibleError(
                        division=0,  # Will be set by caller
                        message="Access denied to this resource",
                    )

                # Handle other errors
                if response.status_code >= 400:
                    error_msg = f"API error: {response.status_code}"
                    try:
                        error_data = response.json()
                        if "error" in error_data:
                            error_msg = error_data["error"].get(
                                "message", {}).get("value", error_msg
                            )
                    except Exception:
                        pass
                    raise ExactOnlineError(error_msg)

                return response

            except httpx.TimeoutException as e:
                if attempt < self.MAX_RETRIES - 1:
                    wait_time = self.RETRY_BACKOFF_BASE ** attempt
                    logger.warning(f"Timeout, retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    continue
                raise NetworkError("Request timed out", e) from e

            except httpx.RequestError as e:
                if attempt < self.MAX_RETRIES - 1:
                    wait_time = self.RETRY_BACKOFF_BASE ** attempt
                    logger.warning(f"Network error, retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    continue
                raise NetworkError("Network connection failed", e) from e

        raise ExactOnlineError("Max retries exceeded")

    async def get_current_division(self) -> int:
        """Get the current user's default division.

        Returns:
            Division code.

        Raises:
            ExactOnlineError: On API errors.
        """
        url = f"{self.base_url}/api/v1/current/Me?$select=CurrentDivision"
        response = await self._request("GET", url)
        data = response.json()

        # Exact Online returns data in 'd.results' array
        results = data.get("d", {}).get("results", [])
        if results:
            return results[0].get("CurrentDivision")
        return None

    async def get_divisions(self) -> list[Division]:
        """Get all accessible divisions.

        Returns:
            List of Division objects sorted by name.

        Raises:
            ExactOnlineError: On API errors.
        """
        current_division = await self.get_current_division()

        url = f"{self.base_url}/api/v1/{current_division}/hrm/Divisions"
        url += "?$select=Code,Description,HID&$orderby=Description"

        response = await self._request("GET", url)
        data = response.json()

        results = data.get("d", {}).get("results", [])

        divisions = []
        for item in results:
            code = item.get("Code")
            if code is not None:
                divisions.append(
                    Division(
                        code=code,
                        name=item.get("Description", f"Division {code}"),
                        is_current=(code == current_division),
                    )
                )

        return sorted(divisions, key=lambda d: d.name)

    async def get(
        self,
        endpoint: str,
        division: int,
        select: str | None = None,
        filter: str | None = None,
        top: int | None = None,
        skip: int | None = None,
        orderby: str | None = None,
    ) -> dict[str, Any]:
        """Make a GET request to any Exact Online API endpoint.

        Args:
            endpoint: API endpoint path (e.g., "crm/Accounts").
            division: Division code.
            select: OData $select parameter.
            filter: OData $filter parameter.
            top: OData $top parameter (max records).
            skip: OData $skip parameter (pagination offset).
            orderby: OData $orderby parameter.

        Returns:
            API response data.

        Raises:
            ExactOnlineError: On API errors.
        """
        url = f"{self.base_url}/api/v1/{division}/{endpoint}"

        # Build query parameters
        params = {}
        if select:
            params["$select"] = select
        if filter:
            params["$filter"] = filter
        if top:
            params["$top"] = str(top)
        if skip:
            params["$skip"] = str(skip)
        if orderby:
            params["$orderby"] = orderby

        if params:
            url += "?" + urlencode(params)

        try:
            response = await self._request("GET", url)
            return response.json()
        except DivisionNotAccessibleError as e:
            raise DivisionNotAccessibleError(division) from e

    async def explore_endpoint(
        self,
        endpoint: str,
        division: int | None = None,
        top: int = 5,
        select: str | None = None,
        filter: str | None = None,
    ) -> ExplorationResult:
        """Explore an API endpoint and return sample data with field info.

        Args:
            endpoint: API endpoint path (e.g., "crm/Accounts").
            division: Division code (defaults to first available).
            top: Max records to return (capped at 25).
            select: OData $select parameter.
            filter: OData $filter parameter.

        Returns:
            ExplorationResult with sample data and available fields.

        Raises:
            ExactOnlineError: On API errors.
        """
        # Cap top at 25 for exploration
        top = min(top, 25)

        # Get default division if not specified
        if division is None:
            divisions = await self.get_divisions()
            if not divisions:
                raise ExactOnlineError("No accessible divisions found")
            division = divisions[0].code

        # Fetch data
        data = await self.get(
            endpoint=endpoint,
            division=division,
            select=select,
            filter=filter,
            top=top,
        )

        # Extract results - handle both d.results (system endpoints) and d as array (data endpoints)
        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        # Extract available fields from first record
        available_fields: list[str] = []
        if results:
            first_record = results[0]
            available_fields = [
                k for k in first_record
                if not k.startswith("__") and k != "__metadata"
            ]

        return ExplorationResult(
            endpoint=endpoint,
            division=division,
            count=len(results),
            data=results,
            available_fields=sorted(available_fields),
        )

    # =========================================================================
    # Revenue Helper Functions (Feature 002-revenue-tools)
    # =========================================================================

    async def get_all_paginated(
        self,
        endpoint: str,
        division: int,
        select: str | None = None,
        filter: str | None = None,
        orderby: str | None = None,
        page_size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Fetch all records from an endpoint with automatic pagination.

        Args:
            endpoint: API endpoint path.
            division: Division code.
            select: OData $select parameter.
            filter: OData $filter parameter.
            orderby: OData $orderby parameter.
            page_size: Records per page (max 1000).

        Returns:
            List of all records from the endpoint.
        """
        all_results: list[dict[str, Any]] = []
        skip = 0

        while True:
            data = await self.get(
                endpoint=endpoint,
                division=division,
                select=select,
                filter=filter,
                top=page_size,
                skip=skip,
                orderby=orderby,
            )

            # Extract results
            d = data.get("d", [])
            if isinstance(d, dict):
                results = d.get("results", [])
            else:
                results = d if isinstance(d, list) else []

            if not results:
                break

            all_results.extend(results)

            # If we got fewer than page_size, we're done
            if len(results) < page_size:
                break

            skip += page_size

        return all_results

    def build_date_filter(
        self,
        start_date: str,
        end_date: str,
        date_field: str = "InvoiceDate",
    ) -> str:
        """Build OData filter for date range.

        Args:
            start_date: Start date in ISO format (YYYY-MM-DD).
            end_date: End date in ISO format (YYYY-MM-DD).
            date_field: Name of the date field to filter on.

        Returns:
            OData filter string.
        """
        return (
            f"{date_field} ge datetime'{start_date}' and "
            f"{date_field} le datetime'{end_date}'"
        )

    def get_period_boundaries(
        self,
        start_date: str,
        end_date: str,
        group_by: str,
    ) -> list[tuple[str, str, str]]:
        """Generate period boundaries for grouping.

        Args:
            start_date: Start date in ISO format (YYYY-MM-DD).
            end_date: End date in ISO format (YYYY-MM-DD).
            group_by: Grouping type - 'month', 'quarter', or 'year'.

        Returns:
            List of (period_key, period_start, period_end) tuples.
        """
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
        periods: list[tuple[str, str, str]] = []

        if group_by == "year":
            current_year = start.year
            while current_year <= end.year:
                period_start = date(current_year, 1, 1)
                period_end = date(current_year, 12, 31)
                # Clamp to requested range
                period_start = max(period_start, start)
                period_end = min(period_end, end)
                periods.append((
                    str(current_year),
                    period_start.isoformat(),
                    period_end.isoformat(),
                ))
                current_year += 1

        elif group_by == "quarter":
            current = start
            while current <= end:
                quarter = (current.month - 1) // 3 + 1
                quarter_start_month = (quarter - 1) * 3 + 1
                quarter_end_month = quarter * 3
                period_start = date(current.year, quarter_start_month, 1)
                # Get last day of quarter
                if quarter_end_month == 12:
                    period_end = date(current.year, 12, 31)
                else:
                    period_end = date(current.year, quarter_end_month + 1, 1) - timedelta(days=1)
                # Clamp to requested range
                period_start = max(period_start, start)
                period_end = min(period_end, end)
                period_key = f"{current.year}-Q{quarter}"
                periods.append((
                    period_key,
                    period_start.isoformat(),
                    period_end.isoformat(),
                ))
                # Move to next quarter
                if quarter == 4:
                    current = date(current.year + 1, 1, 1)
                else:
                    current = date(current.year, quarter_end_month + 1, 1)

        else:  # month
            current = start
            while current <= end:
                period_start = date(current.year, current.month, 1)
                # Get last day of month
                if current.month == 12:
                    period_end = date(current.year, 12, 31)
                else:
                    period_end = date(current.year, current.month + 1, 1) - timedelta(days=1)
                # Clamp to requested range
                period_start = max(period_start, start)
                period_end = min(period_end, end)
                period_key = f"{current.year}-{current.month:02d}"
                periods.append((
                    period_key,
                    period_start.isoformat(),
                    period_end.isoformat(),
                ))
                # Move to next month
                if current.month == 12:
                    current = date(current.year + 1, 1, 1)
                else:
                    current = date(current.year, current.month + 1, 1)

        return periods

    async def fetch_invoices_for_date_range(
        self,
        division: int,
        start_date: str,
        end_date: str,
    ) -> list[dict[str, Any]]:
        """Fetch all processed invoices for a date range.

        Args:
            division: Division code.
            start_date: Start date in ISO format.
            end_date: End date in ISO format.

        Returns:
            List of invoice records with Status=50 (processed).
        """
        date_filter = self.build_date_filter(start_date, end_date)
        full_filter = f"Status eq 50 and {date_filter}"

        return await self.get_all_paginated(
            endpoint="salesinvoice/SalesInvoices",
            division=division,
            select="InvoiceID,InvoiceDate,AmountDC,InvoiceTo,InvoiceToName",
            filter=full_filter,
        )

    def group_invoices_by_period(
        self,
        invoices: list[dict[str, Any]],
        periods: list[tuple[str, str, str]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Group invoices by period based on InvoiceDate.

        Args:
            invoices: List of invoice records.
            periods: List of (period_key, start, end) tuples.

        Returns:
            Dictionary mapping period_key to list of invoices.
        """
        grouped: dict[str, list[dict[str, Any]]] = {p[0]: [] for p in periods}

        for invoice in invoices:
            invoice_date_str = invoice.get("InvoiceDate", "")
            if not invoice_date_str:
                continue

            # Parse Exact Online date format: "/Date(timestamp)/"
            if invoice_date_str.startswith("/Date("):
                timestamp_ms = int(invoice_date_str[6:-2].split("+")[0].split("-")[0])
                invoice_date = date.fromtimestamp(timestamp_ms / 1000)
            else:
                invoice_date = date.fromisoformat(invoice_date_str[:10])

            # Find matching period
            for period_key, period_start, period_end in periods:
                start = date.fromisoformat(period_start)
                end = date.fromisoformat(period_end)
                if start <= invoice_date <= end:
                    grouped[period_key].append(invoice)
                    break

        return grouped

    def calculate_period_revenue(
        self,
        invoices: list[dict[str, Any]],
    ) -> tuple[float, int]:
        """Calculate total revenue and invoice count.

        Args:
            invoices: List of invoice records.

        Returns:
            Tuple of (total_revenue, invoice_count).
        """
        total = sum(float(inv.get("AmountDC", 0) or 0) for inv in invoices)
        return (round(total, 2), len(invoices))

    def aggregate_by_customer(
        self,
        invoices: list[dict[str, Any]],
    ) -> list[CustomerRevenue]:
        """Aggregate invoices by customer.

        Args:
            invoices: List of invoice records.

        Returns:
            List of CustomerRevenue sorted by revenue descending.
        """
        customer_data: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"name": "", "revenue": 0.0, "count": 0}
        )

        total_revenue = 0.0
        for inv in invoices:
            customer_id = inv.get("InvoiceTo") or "unknown"
            customer_name = inv.get("InvoiceToName") or "Unknown"
            amount = float(inv.get("AmountDC", 0) or 0)

            customer_data[customer_id]["name"] = customer_name
            customer_data[customer_id]["revenue"] += amount
            customer_data[customer_id]["count"] += 1
            total_revenue += amount

        # Create CustomerRevenue objects with percentage
        customers: list[CustomerRevenue] = []
        for cust_id, data in customer_data.items():
            pct = (data["revenue"] / total_revenue * 100) if total_revenue > 0 else 0
            customers.append(CustomerRevenue(
                customer_id=cust_id,
                customer_name=data["name"],
                revenue=round(data["revenue"], 2),
                invoice_count=data["count"],
                percentage_of_total=round(pct, 2),
            ))

        # Sort by revenue descending
        customers.sort(key=lambda c: c.revenue, reverse=True)
        return customers

    async def fetch_invoice_lines_with_projects(
        self,
        division: int,
    ) -> list[dict[str, Any]]:
        """Fetch invoice lines that have project references.

        Args:
            division: Division code.

        Returns:
            List of invoice line records with Project != null.

        Note:
            SalesInvoiceLines doesn't have direct date filter.
            Date filtering should be done client-side if needed.
        """
        return await self.get_all_paginated(
            endpoint="salesinvoice/SalesInvoiceLines",
            division=division,
            select="ID,InvoiceID,Project,AmountDC",
            filter="Project ne null",
        )

    async def fetch_projects(
        self,
        division: int,
    ) -> dict[str, dict[str, Any]]:
        """Fetch project metadata.

        Args:
            division: Division code.

        Returns:
            Dictionary mapping project ID to project data.
        """
        projects = await self.get_all_paginated(
            endpoint="project/Projects",
            division=division,
            select="ID,Code,Description,Account,AccountName",
        )

        project_map: dict[str, dict[str, Any]] = {}
        for proj in projects:
            proj_id = proj.get("ID")
            if proj_id:
                project_map[proj_id] = proj

        return project_map

    async def fetch_time_transactions(
        self,
        division: int,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict[str, float]:
        """Fetch hours from TimeTransactions by project.

        Args:
            division: Division code.
            start_date: Optional start date filter.
            end_date: Optional end date filter.

        Returns:
            Dictionary mapping project ID to total hours.
        """
        filter_parts = []
        if start_date and end_date:
            filter_parts.append(self.build_date_filter(start_date, end_date, "Date"))

        transactions = await self.get_all_paginated(
            endpoint="project/TimeTransactions",
            division=division,
            select="ID,Project,Quantity",
            filter=" and ".join(filter_parts) if filter_parts else None,
        )

        hours_by_project: dict[str, float] = defaultdict(float)
        for tx in transactions:
            proj_id = tx.get("Project")
            quantity = tx.get("Quantity", 0) or 0
            if proj_id:
                hours_by_project[proj_id] += float(quantity)

        return dict(hours_by_project)

    def aggregate_by_project(
        self,
        invoice_lines: list[dict[str, Any]],
        project_metadata: dict[str, dict[str, Any]],
        hours_data: dict[str, float] | None = None,
    ) -> list[ProjectRevenue]:
        """Aggregate invoice lines by project.

        Args:
            invoice_lines: List of invoice line records.
            project_metadata: Dictionary of project data by ID.
            hours_data: Optional dictionary of hours by project ID.

        Returns:
            List of ProjectRevenue sorted by revenue descending.
        """
        project_data: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"revenue": 0.0, "count": 0}
        )

        for line in invoice_lines:
            proj_id = line.get("Project")
            if not proj_id:
                continue
            amount = float(line.get("AmountDC", 0) or 0)
            project_data[proj_id]["revenue"] += amount
            project_data[proj_id]["count"] += 1

        # Build ProjectRevenue objects
        projects: list[ProjectRevenue] = []
        for proj_id, data in project_data.items():
            metadata = project_metadata.get(proj_id, {})
            hours = hours_data.get(proj_id) if hours_data else None

            projects.append(ProjectRevenue(
                project_id=proj_id,
                project_code=metadata.get("Code", ""),
                project_name=metadata.get("Description", "Unknown Project"),
                client_id=metadata.get("Account"),
                client_name=metadata.get("AccountName"),
                revenue=round(data["revenue"], 2),
                invoice_count=data["count"],
                hours=round(hours, 2) if hours is not None else None,
            ))

        # Sort by revenue descending
        projects.sort(key=lambda p: p.revenue, reverse=True)
        return projects

    # =========================================================================
    # Financial Reporting Helper Functions (Feature 001-balance-sheet-financial)
    # =========================================================================

    async def fetch_profit_loss_overview(
        self,
        division: int,
    ) -> ProfitLossOverview:
        """Fetch profit and loss overview from Exact Online.

        Args:
            division: Division code.

        Returns:
            ProfitLossOverview with year-over-year comparison data.
        """
        data = await self.get(
            endpoint="read/financial/ProfitLossOverview",
            division=division,
        )

        # Extract results - this endpoint returns d as array
        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        # Default values for empty results
        if not results:
            from datetime import datetime as dt
            current_year = dt.now().year
            return ProfitLossOverview(
                division=division,
                current_year=current_year,
                previous_year=current_year - 1,
                currency_code="EUR",
                revenue_current_year=0.0,
                revenue_previous_year=0.0,
                costs_current_year=0.0,
                costs_previous_year=0.0,
                result_current_year=0.0,
                result_previous_year=0.0,
                current_period=1,
                revenue_current_period=0.0,
                costs_current_period=0.0,
                result_current_period=0.0,
            )

        # P&L Overview returns a single record
        record = results[0]

        return ProfitLossOverview(
            division=division,
            current_year=record.get("CurrentYear", 0),
            previous_year=record.get("PreviousYear", 0),
            currency_code=record.get("CurrencyCode", "EUR"),
            revenue_current_year=float(record.get("RevenueCurrentYear", 0) or 0),
            revenue_previous_year=float(record.get("RevenuePreviousYear", 0) or 0),
            costs_current_year=float(record.get("CostsCurrentYear", 0) or 0),
            costs_previous_year=float(record.get("CostsPreviousYear", 0) or 0),
            result_current_year=float(record.get("ResultCurrentYear", 0) or 0),
            result_previous_year=float(record.get("ResultPreviousYear", 0) or 0),
            current_period=record.get("CurrentPeriod", 1),
            revenue_current_period=float(record.get("RevenueCurrentPeriod", 0) or 0),
            costs_current_period=float(record.get("CostsCurrentPeriod", 0) or 0),
            result_current_period=float(record.get("ResultCurrentPeriod", 0) or 0),
        )

    async def fetch_gl_account_by_code(
        self,
        division: int,
        account_code: str,
    ) -> dict[str, Any] | None:
        """Fetch a GL account by its code.

        Args:
            division: Division code.
            account_code: GL account code (e.g., "1300").

        Returns:
            GL account data dict or None if not found.

        Raises:
            ValueError: If account_code contains invalid characters.
        """
        safe_code = sanitize_odata_string(account_code)
        data = await self.get(
            endpoint="financial/GLAccounts",
            division=division,
            filter=f"Code eq '{safe_code}'",
            select="ID,Code,Description,BalanceType,Type,TypeDescription",
            top=1,
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        return results[0] if results else None

    async def fetch_reporting_balance(
        self,
        division: int,
        gl_account_id: str,
        year: int | None = None,
        period: int | None = None,
    ) -> dict[str, Any] | None:
        """Fetch reporting balance for a specific GL account.

        Args:
            division: Division code.
            gl_account_id: GL account GUID.
            year: Fiscal year (optional, defaults to current).
            period: Reporting period 1-12 (optional, defaults to current).

        Returns:
            Reporting balance data dict or None if not found.
        """
        filter_parts = [f"GLAccountID eq guid'{gl_account_id}'"]

        if year:
            filter_parts.append(f"ReportingYear eq {year}")
        if period:
            filter_parts.append(f"ReportingPeriod eq {period}")

        data = await self.get(
            endpoint="financial/ReportingBalance",
            division=division,
            filter=" and ".join(filter_parts),
            select="ID,GLAccountID,GLAccountCode,GLAccountDescription,Amount,AmountDebit,AmountCredit,BalanceType,Type,TypeDescription,ReportingYear,ReportingPeriod",
            top=1,
            orderby="ReportingYear desc,ReportingPeriod desc",
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        return results[0] if results else None

    async def fetch_all_balance_sheet_balances(
        self,
        division: int,
        year: int | None = None,
        period: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all balance sheet account balances.

        Args:
            division: Division code.
            year: Fiscal year (optional).
            period: Reporting period (optional).

        Returns:
            List of reporting balance records for balance sheet accounts.
        """
        filter_parts = ["BalanceType eq 'B'"]

        if year:
            filter_parts.append(f"ReportingYear eq {year}")
        if period:
            filter_parts.append(f"ReportingPeriod eq {period}")

        return await self.get_all_paginated(
            endpoint="financial/ReportingBalance",
            division=division,
            filter=" and ".join(filter_parts),
            select="ID,GLAccountID,GLAccountCode,GLAccountDescription,Amount,AmountDebit,AmountCredit,BalanceType,Type,TypeDescription,ReportingYear,ReportingPeriod",
        )

    def aggregate_balances_by_category(
        self,
        balances: list[dict[str, Any]],
        division: int,
        year: int,
        period: int,
    ) -> BalanceSheetSummary:
        """Aggregate balance records into balance sheet categories.

        Args:
            balances: List of reporting balance records.
            division: Division code.
            year: Reporting year.
            period: Reporting period.

        Returns:
            BalanceSheetSummary with categorized totals.
        """
        category_totals: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"amount": 0.0, "count": 0}
        )

        for balance in balances:
            account_type = balance.get("Type", 0)
            amount = float(balance.get("Amount", 0) or 0)

            # Look up category from mapping
            category_info = ACCOUNT_TYPE_CATEGORIES.get(account_type)
            if category_info:
                category, name = category_info
                if category != "pl":  # Skip P&L accounts
                    key = f"{category}:{name}"
                    category_totals[key]["amount"] += amount
                    category_totals[key]["count"] += 1
                    category_totals[key]["category"] = category
                    category_totals[key]["name"] = name
            else:
                # Unknown type - classify by type description if available
                type_desc = balance.get("TypeDescription", "Unknown")
                # Default to assets for unknown balance sheet types
                key = f"assets:{type_desc}"
                category_totals[key]["amount"] += amount
                category_totals[key]["count"] += 1
                category_totals[key]["category"] = "assets"
                category_totals[key]["name"] = type_desc

        # Build category lists
        assets: list[BalanceSheetCategory] = []
        liabilities: list[BalanceSheetCategory] = []
        equity: list[BalanceSheetCategory] = []

        for _key, data in category_totals.items():
            category_obj = BalanceSheetCategory(
                name=data["name"],
                amount=round(data["amount"], 2),
                account_count=data["count"],
            )
            if data["category"] == "assets":
                assets.append(category_obj)
            elif data["category"] == "liabilities":
                liabilities.append(category_obj)
            elif data["category"] == "equity":
                equity.append(category_obj)

        # Calculate totals
        total_assets = sum(c.amount for c in assets)
        total_liabilities = sum(c.amount for c in liabilities)
        total_equity = sum(c.amount for c in equity)

        return BalanceSheetSummary(
            division=division,
            reporting_year=year,
            reporting_period=period,
            currency_code="EUR",
            total_assets=round(total_assets, 2),
            total_liabilities=round(total_liabilities, 2),
            total_equity=round(total_equity, 2),
            assets=sorted(assets, key=lambda c: c.amount, reverse=True),
            liabilities=sorted(liabilities, key=lambda c: c.amount, reverse=True),
            equity=sorted(equity, key=lambda c: c.amount, reverse=True),
        )

    async def fetch_filtered_balances(
        self,
        division: int,
        balance_type: str | None = None,
        account_type: int | None = None,
        year: int | None = None,
        period: int | None = None,
    ) -> list[GLAccountBalance]:
        """Fetch GL account balances with optional filters.

        Args:
            division: Division code.
            balance_type: "B" for balance sheet, "W" for P&L (optional).
            account_type: Account type code (optional).
            year: Fiscal year (optional).
            period: Reporting period (optional).

        Returns:
            List of GLAccountBalance objects.

        Raises:
            ValueError: If balance_type contains invalid characters.
        """
        filter_parts = []

        if balance_type:
            safe_balance_type = sanitize_odata_string(balance_type)
            filter_parts.append(f"BalanceType eq '{safe_balance_type}'")
        if account_type:
            filter_parts.append(f"Type eq {account_type}")
        if year:
            filter_parts.append(f"ReportingYear eq {year}")
        if period:
            filter_parts.append(f"ReportingPeriod eq {period}")

        records = await self.get_all_paginated(
            endpoint="financial/ReportingBalance",
            division=division,
            filter=" and ".join(filter_parts) if filter_parts else None,
            select="ID,GLAccountID,GLAccountCode,GLAccountDescription,Amount,AmountDebit,AmountCredit,BalanceType,Type,TypeDescription,ReportingYear,ReportingPeriod",
            orderby="GLAccountCode",
        )

        return [
            GLAccountBalance(
                gl_account_id=r.get("GLAccountID", ""),
                gl_account_code=r.get("GLAccountCode", ""),
                gl_account_description=r.get("GLAccountDescription", ""),
                amount=float(r.get("Amount", 0) or 0),
                amount_debit=float(r.get("AmountDebit", 0) or 0),
                amount_credit=float(r.get("AmountCredit", 0) or 0),
                balance_type=r.get("BalanceType", ""),
                account_type=r.get("Type", 0),
                account_type_description=r.get("TypeDescription", ""),
                reporting_year=r.get("ReportingYear", 0),
                reporting_period=r.get("ReportingPeriod", 0),
            )
            for r in records
        ]

    async def fetch_aging_receivables(
        self,
        division: int,
    ) -> list[AgingEntry]:
        """Fetch aging receivables report.

        Args:
            division: Division code.

        Returns:
            List of AgingEntry objects for outstanding receivables.
        """
        data = await self.get(
            endpoint="read/financial/AgingReceivablesList",
            division=division,
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        return [
            AgingEntry(
                account_id=r.get("AccountId", "") or "",
                account_code=r.get("AccountCode", "") or "",
                account_name=r.get("AccountName", "") or "",
                total_amount=float(r.get("TotalAmount", 0) or 0),
                age_0_30=float(r.get("AgeGroup1Amount", 0) or 0),
                age_31_60=float(r.get("AgeGroup2Amount", 0) or 0),
                age_61_90=float(r.get("AgeGroup3Amount", 0) or 0),
                age_over_90=float(r.get("AgeGroup4Amount", 0) or 0),
                currency_code=r.get("CurrencyCode", "EUR") or "EUR",
            )
            for r in results
        ]

    async def fetch_aging_payables(
        self,
        division: int,
    ) -> list[AgingEntry]:
        """Fetch aging payables report.

        Args:
            division: Division code.

        Returns:
            List of AgingEntry objects for outstanding payables.
        """
        data = await self.get(
            endpoint="read/financial/AgingPayablesList",
            division=division,
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        return [
            AgingEntry(
                account_id=r.get("AccountId", "") or "",
                account_code=r.get("AccountCode", "") or "",
                account_name=r.get("AccountName", "") or "",
                total_amount=float(r.get("TotalAmount", 0) or 0),
                age_0_30=float(r.get("AgeGroup1Amount", 0) or 0),
                age_31_60=float(r.get("AgeGroup2Amount", 0) or 0),
                age_61_90=float(r.get("AgeGroup3Amount", 0) or 0),
                age_over_90=float(r.get("AgeGroup4Amount", 0) or 0),
                currency_code=r.get("CurrencyCode", "EUR") or "EUR",
            )
            for r in results
        ]

    async def fetch_open_receivables(
        self,
        division: int,
        top: int = 100,
        account_code: str | None = None,
        overdue_only: bool = False,
    ) -> list[OpenReceivable]:
        """Fetch open receivables from cashflow/Receivables endpoint.

        Args:
            division: Division code.
            top: Maximum records to return (1-1000, default 100).
            account_code: Filter by customer account code (optional).
            overdue_only: Only return items past their due date (optional).

        Returns:
            List of OpenReceivable objects for outstanding invoices/credits.
        """
        # Build OData filter for open items
        filters = ["IsFullyPaid eq false"]
        if account_code:
            safe_code = sanitize_odata_string(account_code.strip())
            filters.append(f"trim(AccountCode) eq '{safe_code}'")
        if overdue_only:
            today = date.today().strftime("%Y-%m-%d")
            filters.append(f"DueDate lt datetime'{today}'")

        # Select only needed fields
        select_fields = [
            "AccountCode",
            "AccountName",
            "InvoiceNumber",
            "InvoiceDate",
            "DueDate",
            "TransactionAmountDC",
            "AmountDC",
            "Description",
            "PaymentConditionDescription",
            "Currency",
        ]

        data = await self.get(
            endpoint="cashflow/Receivables",
            division=division,
            filter=" and ".join(filters),
            select=",".join(select_fields),
            top=min(top, 1000),
            orderby="DueDate",
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        today = date.today()
        receivables = []
        for r in results:
            # Parse dates
            invoice_date = parse_odata_date(r.get("InvoiceDate"))
            due_date = parse_odata_date(r.get("DueDate"))

            # Calculate days overdue
            days_overdue = 0
            if due_date:
                try:
                    due_dt = datetime.strptime(due_date, "%Y-%m-%d").date()
                    days_overdue = (today - due_dt).days
                except ValueError:
                    pass

            # Get amounts - AmountDC negative = we receive money, positive = credit
            amount_dc = float(r.get("AmountDC", 0) or 0)
            transaction_amount = float(r.get("TransactionAmountDC", 0) or 0)

            receivables.append(
                OpenReceivable(
                    account_code=(r.get("AccountCode") or "").strip(),
                    account_name=r.get("AccountName") or "",
                    invoice_number=int(r.get("InvoiceNumber", 0) or 0),
                    invoice_date=invoice_date or "",
                    due_date=due_date or "",
                    original_amount=abs(transaction_amount),
                    remaining_amount=abs(amount_dc),
                    is_credit=amount_dc > 0,
                    description=r.get("Description") or "",
                    payment_terms=r.get("PaymentConditionDescription") or "",
                    days_overdue=days_overdue,
                    currency=r.get("Currency") or "EUR",
                )
            )

        return receivables

    async def fetch_transaction_lines(
        self,
        division: int,
        gl_account_id: str,
        year: int | None = None,
        period: int | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 100,
    ) -> list[TransactionLine]:
        """Fetch transaction lines for a specific GL account.

        Args:
            division: Division code.
            gl_account_id: GL account GUID.
            year: Fiscal year filter (optional).
            period: Reporting period filter (optional, used with year).
            start_date: Start date filter YYYY-MM-DD (optional).
            end_date: End date filter YYYY-MM-DD (optional).
            limit: Maximum records to return (default 100).

        Returns:
            List of TransactionLine objects.
        """
        filter_parts = [f"GLAccount eq guid'{gl_account_id}'"]

        if year:
            filter_parts.append(f"FinancialYear eq {year}")
        if period:
            filter_parts.append(f"FinancialPeriod eq {period}")
        if start_date and end_date:
            filter_parts.append(self.build_date_filter(start_date, end_date, "Date"))

        data = await self.get(
            endpoint="financialtransaction/TransactionLines",
            division=division,
            filter=" and ".join(filter_parts),
            select="ID,Date,FinancialYear,FinancialPeriod,GLAccountCode,GLAccountDescription,Description,AmountDC,EntryNumber,JournalCode",
            top=limit,
            orderby="Date desc",
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        transactions: list[TransactionLine] = []
        for r in results:
            # Parse date from Exact Online format
            date_str = r.get("Date", "")
            if date_str.startswith("/Date("):
                timestamp_ms = int(date_str[6:-2].split("+")[0].split("-")[0])
                from datetime import datetime as dt
                parsed_date = dt.fromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%d")
            else:
                parsed_date = date_str[:10] if date_str else ""

            transactions.append(TransactionLine(
                id=r.get("ID", ""),
                date=parsed_date,
                financial_year=r.get("FinancialYear", 0),
                financial_period=r.get("FinancialPeriod", 0),
                gl_account_code=r.get("GLAccountCode", ""),
                gl_account_description=r.get("GLAccountDescription", ""),
                description=r.get("Description", "") or "",
                amount=float(r.get("AmountDC", 0) or 0),
                entry_number=r.get("EntryNumber", 0),
                journal_code=r.get("JournalCode", "") or "",
            ))

        return transactions

    # =========================================================================
    # Bank & Purchase Data Functions (Feature 004-bank-purchase-data)
    # =========================================================================

    async def fetch_bank_transactions(
        self,
        division: int,
        top: int = 100,
        start_date: str | None = None,
        end_date: str | None = None,
        gl_account_code: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch bank transaction lines from financialtransaction/BankEntryLines.

        Args:
            division: Division code.
            top: Maximum records to return (1-1000, default 100).
            start_date: Filter from date (YYYY-MM-DD, optional).
            end_date: Filter to date (YYYY-MM-DD, optional).
            gl_account_code: Filter by bank GL account code (e.g., "1055", optional).

        Returns:
            List of bank transaction records.
        """
        filters = []
        if start_date:
            filters.append(f"Date ge datetime'{start_date}'")
        if end_date:
            filters.append(f"Date le datetime'{end_date}'")
        if gl_account_code:
            safe_code = sanitize_odata_string(gl_account_code.strip())
            filters.append(f"trim(GLAccountCode) eq '{safe_code}'")

        select_fields = [
            "ID",
            "Date",
            "Description",
            "AmountDC",
            "AccountCode",
            "AccountName",
            "GLAccountCode",
            "GLAccountDescription",
            "EntryNumber",
            "DocumentSubject",
            "Notes",
            "OurRef",
        ]

        data = await self.get(
            endpoint="financialtransaction/BankEntryLines",
            division=division,
            filter=" and ".join(filters) if filters else None,
            select=",".join(select_fields),
            top=min(top, 1000),
            orderby="Date desc",
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        return results

    async def fetch_purchase_invoices(
        self,
        division: int,
        top: int = 100,
        start_date: str | None = None,
        end_date: str | None = None,
        supplier_code: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch purchase invoices from purchase/PurchaseInvoices.

        Args:
            division: Division code.
            top: Maximum records to return (1-1000, default 100).
            start_date: Invoice date from (YYYY-MM-DD, optional).
            end_date: Invoice date to (YYYY-MM-DD, optional).
            supplier_code: Filter by supplier account code (optional).

        Returns:
            List of purchase invoice records.

        Note:
            This endpoint may require the Purchase module subscription.
            If the module is not available, a DivisionNotAccessibleError is raised.
        """
        filters = []
        if start_date:
            filters.append(f"InvoiceDate ge datetime'{start_date}'")
        if end_date:
            filters.append(f"InvoiceDate le datetime'{end_date}'")
        if supplier_code:
            safe_code = sanitize_odata_string(supplier_code.strip())
            filters.append(f"trim(SupplierCode) eq '{safe_code}'")

        select_fields = [
            "ID",
            "InvoiceNumber",
            "InvoiceDate",
            "DueDate",
            "SupplierCode",
            "SupplierName",
            "AmountDC",
            "Currency",
            "Status",
            "StatusDescription",
            "Description",
            "PaymentConditionDescription",
        ]

        data = await self.get(
            endpoint="purchase/PurchaseInvoices",
            division=division,
            filter=" and ".join(filters) if filters else None,
            select=",".join(select_fields),
            top=min(top, 1000),
            orderby="InvoiceDate desc",
        )

        d = data.get("d", [])
        if isinstance(d, dict):
            results = d.get("results", [])
        else:
            results = d if isinstance(d, list) else []

        return results
