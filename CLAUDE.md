# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FatSecret MCP Server - A Model Context Protocol server for the FatSecret nutrition API, deployed on Cloudflare Workers. Implements OAuth 1.0a authentication with HMAC-SHA1 signing.

## Build & Development Commands

```bash
npm install           # Install dependencies
npm run dev           # Run local dev server (wrangler dev on port 8787)
npm run deploy        # Deploy to Cloudflare Workers
npm run type-check    # TypeScript type checking
npm run test          # Run tests
npm run test:run      # Run tests once
npm run format        # Format code with Biome
npm run lint:fix      # Lint and auto-fix with Biome
```

## Architecture

```
src/
├── index.ts              # Entry point - exports Hono app & Durable Object
├── app.ts                # Hono app with CORS, routes, error handling
├── mcp-agent.ts          # FatSecretMCP class with all MCP tools
├── mcp-handlers.ts       # MCP handler exports (streamableHTTP, SSE)
├── middleware/
│   └── auth.ts           # Bearer token authentication
├── lib/
│   ├── oauth.ts          # OAuth 1.0a signing (HMAC-SHA1)
│   ├── client.ts         # FatSecretClient API wrapper
│   ├── schemas.ts        # Zod schemas for validation
│   ├── transforms.ts     # Date conversion, data cleaning
│   ├── errors.ts         # Error handling utilities
│   └── token-storage.ts  # AES-GCM encrypted KV storage
└── routes/
    ├── mcp.ts            # MCP protocol endpoints
    ├── oauth.ts          # FatSecret OAuth flow
    └── utility.ts        # Health, home page
```

**Key Technologies**: Cloudflare Workers, Hono, MCP SDK, Zod, Durable Objects, KV

## OAuth 1.0a Flow

1. `POST /oauth/setup` with `clientId`, `clientSecret` → returns `state` + `authorizationUrl`
2. User visits authorization URL, gets verifier code
3. `POST /oauth/complete` with `state`, `verifier` → returns `sessionToken`
4. Use `sessionToken` as Bearer token for MCP requests

## MCP Tools

- `search_foods`, `get_food` - Food database (no user auth needed after setup)
- `search_recipes`, `get_recipe` - Recipe database
- `get_user_profile`, `get_user_food_entries`, `add_food_entry`, `get_weight_month` - User data (requires OAuth)
- `check_auth_status` - Authentication status

## Configuration

**Cloudflare Secrets** (set via `wrangler secret put`):
- `COOKIE_ENCRYPTION_KEY` - 64-char hex string for AES-GCM encryption

**KV Namespace**: `OAUTH_KV` - Stores encrypted session data

**Session Data** (encrypted in KV):
- `clientId`, `clientSecret` - User's FatSecret API credentials
- `accessToken`, `accessTokenSecret` - OAuth tokens
- `userId` - FatSecret user ID

## Code Patterns

- OAuth signing in `src/lib/oauth.ts` - RFC 5849 compliant HMAC-SHA1
- API client in `src/lib/client.ts` - All FatSecret API methods
- Date format: YYYY-MM-DD ↔ days since Unix epoch (FatSecret format)
- Response parsing: JSON with querystring fallback (FatSecret inconsistency)

## Deployment

```bash
# 1. Create KV namespaces
npx wrangler kv namespace create OAUTH_KV
npx wrangler kv namespace create OAUTH_KV --env dev

# 2. Update wrangler.jsonc with the namespace IDs from step 1

# 3. Generate encryption key
openssl rand -hex 32

# 4. Set secrets
npx wrangler secret put COOKIE_ENCRYPTION_KEY
npx wrangler secret put COOKIE_ENCRYPTION_KEY --env dev

# 5. Deploy
npm run deploy
```
