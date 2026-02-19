/**
 * FatSecret MCP Server - Main Hono Application
 */

import { Hono } from "hono";
import { safeLogError } from "./lib/errors.js";

export const APP_VERSION = "0.2.0";
import oauth2Routes from "./routes/oauth2.js";
import oauthRoutes from "./routes/oauth.js";
import { createMcpRoutes } from "./routes/mcp.js";
import utilityRoutes from "./routes/utility.js";
import { mcpHandlers } from "./mcp-handlers.js";
import type { SessionData } from "./lib/schemas.js";

// Variables interface for Hono context
interface Variables {
	sessionToken?: string;
	sessionData?: SessionData;
}

export type AppEnv = { Bindings: Env; Variables: Variables };

// Create main Hono app with proper TypeScript types
const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Paths that use Bearer auth (not cookies) and need open CORS for MCP clients
const OPEN_CORS_PREFIXES = ["/mcp", "/sse", "/.well-known", "/health"];
const OPEN_CORS_EXACT = ["/oauth2/token", "/oauth2/register"];

function needsOpenCors(path: string): boolean {
	return OPEN_CORS_PREFIXES.some((p) => path.startsWith(p)) || OPEN_CORS_EXACT.includes(path);
}

// Global CORS and security headers middleware
app.use("*", async (c, next) => {
	const path = new URL(c.req.url).pathname;
	const isOpen = needsOpenCors(path);

	// Handle OPTIONS preflight requests
	if (c.req.method === "OPTIONS") {
		const selfOrigin = new URL(c.req.url).origin;
		const requestOrigin = c.req.header("Origin") || "";
		const corsOrigin = isOpen ? "*" : requestOrigin === selfOrigin ? requestOrigin : "";
		return new Response(null, {
			status: 204,
			headers: {
				...(corsOrigin ? { "Access-Control-Allow-Origin": corsOrigin } : {}),
				...(!isOpen && corsOrigin ? { Vary: "Origin" } : {}),
				"Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type, Authorization",
				"Access-Control-Max-Age": "86400",
			},
		});
	}

	await next();

	// CORS: open for MCP/Bearer routes, same-origin only for cookie routes
	if (isOpen) {
		c.res.headers.set("Access-Control-Allow-Origin", "*");
	} else {
		const origin = c.req.header("Origin");
		const selfOrigin = new URL(c.req.url).origin;
		if (origin === selfOrigin) {
			c.res.headers.set("Access-Control-Allow-Origin", origin);
		}
		c.res.headers.append("Vary", "Origin");
	}
	c.res.headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
	c.res.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");

	// Security headers
	c.res.headers.set("X-Content-Type-Options", "nosniff");
	c.res.headers.set("X-Frame-Options", "DENY");
	c.res.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
	c.res.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
	c.res.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
	c.res.headers.set(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
	);
});

// Error handling middleware
app.onError((err, c) => {
	safeLogError("Unhandled error", err);
	return c.json(
		{
			error: "internal_server_error",
			message: "An unexpected error occurred",
		},
		500,
	);
});

// Mount routes (order matters!)
app.route("/", oauth2Routes); // OAuth 2.0 AS (metadata, DCR, authorize, token)
app.route("/", oauthRoutes); // FatSecret OAuth 1.0a routes
app.route("/", createMcpRoutes(mcpHandlers)); // MCP endpoints
app.route("/", utilityRoutes); // Health, home, etc.

// 404 handler
app.notFound((c) => {
	return c.text("Not found", 404);
});

export default app;
export type { Variables };
