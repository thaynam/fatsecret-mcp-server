# FatSecret MCP Server

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server for the [FatSecret](https://platform.fatsecret.com/) nutrition API, deployed on Cloudflare Workers.

## MCP Tools

| Tool                    | Description                                       |
| ----------------------- | ------------------------------------------------- |
| `search_foods`          | Search the FatSecret food database                |
| `get_food`              | Get detailed nutrition info for a food            |
| `search_recipes`        | Search for recipes                                |
| `get_recipe`            | Get recipe details, ingredients, and instructions |
| `get_user_profile`      | Get the authenticated user's profile              |
| `get_user_food_entries` | Get food diary entries for a date                 |
| `add_food_entry`        | Log a food entry to the user's diary              |
| `get_weight_month`      | Get weight entries for a month                    |
| `check_auth_status`     | Check current authentication status               |

## Self-Hosting

### Prerequisites

- A [FatSecret developer account](https://platform.fatsecret.com/api/) with API credentials
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed

### Deploy

```bash
# Clone and install
git clone https://github.com/fcoury/fatsecret-mcp.git
cd fatsecret-mcp
npm install

# Create KV namespace and note the ID
npx wrangler kv namespace create OAUTH_KV

# Update wrangler.jsonc with your KV namespace ID

# Set the encryption secret (generate with: openssl rand -hex 32)
npx wrangler secret put COOKIE_ENCRYPTION_KEY

# Deploy
npm run deploy
```

## Usage

1. Visit your deployed server URL (e.g. `https://fatsecret-mcp-server.<you>.workers.dev`)
2. Click **Setup Your Account**
3. Enter your FatSecret Client ID, Client Secret, and Consumer Secret
4. Connect your FatSecret account via OAuth
5. Copy the MCP configuration shown on the setup page into your MCP client

The configuration looks like:

```json
{
  "mcpServers": {
    "fatsecret": {
      "url": "https://fatsecret-mcp-server.<you>.workers.dev/mcp",
      "transport": {
        "type": "http",
        "headers": {
          "Authorization": "Bearer <your-session-token>"
        }
      }
    }
  }
}
```

## Development

```bash
npm run dev          # Local dev server on port 8787
npm run test         # Run tests (vitest)
npm run test:run     # Run tests once
npm run type-check   # TypeScript type checking
npm run format       # Format with Biome
npm run lint:fix     # Lint and auto-fix with Biome
```

## License

MIT
