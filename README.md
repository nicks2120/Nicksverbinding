# exactonline-mcp

A Model Context Protocol (MCP) server providing read-only access to Exact Online accounting data. 
## Features

- **18 tools** for querying Exact Online data
- **Revenue analysis** - by period, customer, or project with year-over-year comparison
- **Financial reporting** - P&L overview, balance sheet, GL account balances
- **Aging reports** - outstanding receivables and payables by age bucket
- **Open receivables** - individual invoice detail, customer-specific views, overdue tracking
- **Bank & purchase data** - bank transaction lines, purchase invoices from suppliers
- **Discovery tools** - explore any Exact Online API endpoint

## Security Considerations

**This MCP server is read-only by design.** It only performs GET requests to the Exact Online API, so it cannot modify, delete, or corrupt your accounting data.

However, be aware that:

- **Data exposure risk**: Your financial data (revenue, customer names, account balances, invoices) is accessible to the LLM. If you use other MCP tools that can send data externally (email, webhooks, file uploads), sensitive information could potentially be leaked.
- **LLM guardrails vary**: Claude has strong guardrails, but other LLMs or custom configurations may not. Be cautious when using this MCP with less restricted models.
- **Conversation history**: Your queries and the returned financial data may be stored in conversation logs depending on your LLM provider's data retention policies.

**Recommendations**:
- Only enable this MCP server when you need it
- Review what other MCP tools are active in your configuration
- Be mindful of what financial data you query in shared or logged environments

## Prerequisites

Before you begin, ensure you have:

- **Python 3.11 or higher** - Check with `python --version`
- **uv package manager** - [Installation guide](https://docs.astral.sh/uv/getting-started/installation/)
- **Exact Online account** with API access enabled
- **ngrok account** (free) - [Sign up at ngrok.com](https://ngrok.com/)

## Installation

### 1. Install uv (if not already installed)

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Clone and install

```bash
git clone https://github.com/TimPelgrim/exactonline-mcp.git
cd exactonline-mcp
uv sync
```

### 3. Create configuration file

Create a `.env` file in the project root:

```env
EXACT_ONLINE_CLIENT_ID=your_client_id
EXACT_ONLINE_CLIENT_SECRET=your_client_secret
EXACT_ONLINE_REGION=nl
```

Replace with your actual credentials (see next section).

## Updating

We regularly release updates with new features, bug fixes, and security improvements. We recommend checking for updates periodically.

### How to update

Open Terminal, then run these commands:

```bash
# 1. Go to the installation folder
cd exactonline-mcp

# 2. Download the latest version
git pull origin main

# 3. Update dependencies
uv sync
```

After updating, **restart Claude Desktop** to use the new version.

### Check your current version

To see which version you have installed:

```bash
cd exactonline-mcp
git describe --tags --always
```

This will show something like `v0.1.0` (a release) or `v0.1.0-5-g1234abc` (5 commits after v0.1.0).

### What's new?

You can check what changed since your last update:

- **On GitHub**: Visit the [Releases page](https://github.com/TimPelgrim/exactonline-mcp/releases) for release notes
- **In Terminal**: Run `git log --oneline v0.1.0..HEAD` to see recent changes

### Release history

| Version | Date | Highlights |
|---------|------|------------|
| v0.2.0 | Dec 2024 | Added 5 new tools: open receivables (3), bank & purchase data (2) |
| v0.1.0 | Dec 2024 | Initial release with 13 tools for revenue, financial reporting, and discovery |

## Exact Online App Setup

To get your API credentials:

1. Go to the [Exact Online App Center](https://apps.exactonline.com/)
2. Sign in with your Exact Online account
3. Click **"Manage my apps"** → **"Add a new application"**
4. Fill in the app details:
   - **Name**: e.g., "MCP Server"
   - **Redirect URI**: Your ngrok URL + `/callback` (see Authentication section)
5. After creating the app, copy the **Client ID** and **Client Secret** to your `.env` file

## Authentication

### Why ngrok?

Exact Online requires a publicly accessible HTTPS URL for the OAuth callback. They reject `localhost` URLs, so we use ngrok to create a secure tunnel.

### Setup ngrok

1. Install ngrok: `brew install ngrok` (macOS) or [download](https://ngrok.com/download)
2. Authenticate: `ngrok config add-authtoken YOUR_TOKEN` (get token from ngrok dashboard)
3. Start the tunnel:

```bash
ngrok http 8080
```

4. Copy the HTTPS URL (e.g., `https://abc123.ngrok.io`)

### Configure redirect URI

1. Go back to your Exact Online app settings
2. Update the **Redirect URI** to: `https://YOUR-NGROK-URL/callback`

### Run authentication

With ngrok running in a separate terminal:

```bash
EXACT_ONLINE_REDIRECT_URI=https://YOUR-NGROK-URL/callback uv run python -m exactonline_mcp.auth
```

This will:
1. Open your browser for Exact Online login
2. Request permission to access your data
3. Store tokens securely in your system keyring

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "exactonline": {
      "command": "uv",
      "args": ["--directory", "/path/to/exactonline-mcp", "run", "python", "-m", "exactonline_mcp"],
      "env": {
        "EXACT_ONLINE_CLIENT_ID": "your_client_id",
        "EXACT_ONLINE_CLIENT_SECRET": "your_client_secret",
        "EXACT_ONLINE_REGION": "nl"
      }
    }
  }
}
```

Replace `/path/to/exactonline-mcp` with the actual path to your installation.

## Available Tools

### Discovery Tools
| Tool | Description |
|------|-------------|
| `list_divisions` | List accessible Exact Online divisions (administraties) |
| `explore_endpoint` | Explore any API endpoint with sample data |
| `list_endpoints` | Browse known API endpoints by category |

### Revenue Tools
| Tool | Description |
|------|-------------|
| `get_revenue_by_period` | Revenue totals by month/quarter/year with year-over-year comparison |
| `get_revenue_by_customer` | Customer revenue rankings with invoice counts |
| `get_revenue_by_project` | Project-based revenue with optional hours tracking |

### Financial Reporting Tools
| Tool | Description |
|------|-------------|
| `get_profit_loss_overview` | P&L summary with year-over-year comparison |
| `get_gl_account_balance` | Balance for a specific GL account (grootboekrekening) |
| `get_balance_sheet_summary` | Balance sheet totals by category (assets, liabilities, equity) |
| `list_gl_account_balances` | List accounts with balances, filterable by type |
| `get_aging_receivables` | Outstanding customer invoices by age bucket (0-30, 31-60, 61-90, >90 days) |
| `get_aging_payables` | Outstanding supplier invoices by age bucket |
| `get_gl_account_transactions` | Drill down into individual transactions for an account |

### Open Receivables Tools
| Tool | Description |
|------|-------------|
| `get_open_receivables` | List open invoices with filtering (by customer, overdue only) |
| `get_customer_open_items` | All open items for a specific customer |
| `get_overdue_receivables` | Overdue receivables sorted by days overdue |

### Bank & Purchase Data Tools
| Tool | Description |
|------|-------------|
| `get_bank_transactions` | Bank transaction lines with date/account filtering |
| `get_purchase_invoices` | Purchase invoices from suppliers (requires Purchase module) |

## Example Prompts

```
"Show me revenue by quarter for 2024"
"Who are our top 5 customers?"
"What's the revenue per project this year?"
"Compare Q1 revenue to last year"
"Show me the profit and loss overview"
"What's the balance on account 1300 (Debiteuren)?"
"Show me the balance sheet summary"
"List all P&L accounts with balances"
"Show aging receivables - who owes us money?"
"What transactions were made to account 8000 this year?"
"Show me all open invoices"
"Which invoices are overdue?"
"What's outstanding for customer 400?"
"Show invoices more than 30 days overdue"
"Show bank transactions from last month"
"What payments did we make from the ING account?"
"List purchase invoices from December"
```

## Troubleshooting

### "Division not accessible"

This error means the API endpoint requires a module that's not enabled for your Exact Online subscription. For example, `project/Projects` requires the Project module.

**Solution**: Use `list_divisions` to see which divisions you have access to, and check your Exact Online subscription for available modules.

### Authentication failed / Token expired

Tokens expire after 30 days of inactivity.

**Solution**: Re-run the authentication flow:
```bash
EXACT_ONLINE_REDIRECT_URI=https://YOUR-NGROK-URL/callback uv run python -m exactonline_mcp.auth
```

### ngrok tunnel errors

Common issues:
- **Tunnel not running**: Make sure ngrok is running in a separate terminal
- **URL changed**: ngrok free tier gives a new URL each session - update your redirect URI
- **Rate limited**: Wait a few minutes and try again

**Solution**: Restart ngrok and update the redirect URI in both Exact Online app settings and your auth command.

### Rate limit errors

Exact Online limits API calls to 60 per minute.

**Solution**: The server has built-in retry logic. If you see rate limit errors, wait a minute and try again.

### "Please add a $select or $top=1 statement"

Some Exact Online endpoints require explicit field selection.

**Solution**: Use the `select` parameter when calling `explore_endpoint`, or use the dedicated tools which handle this automatically.

## License

MIT
