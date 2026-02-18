/**
 * FatSecret MCP Server - Main Hono Application
 */

import { Hono } from "hono";

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

// Create main Hono app with proper TypeScript types
const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Global CORS middleware
app.use("*", async (c, next) => {
	// Handle OPTIONS preflight requests
	if (c.req.method === "OPTIONS") {
		return new Response(null, {
			status: 204,
			headers: {
				"Access-Control-Allow-Origin": "*",
				"Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type, Authorization",
				"Access-Control-Max-Age": "86400",
			},
		});
	}

	await next();

	// Add CORS headers to all responses
	c.res.headers.set("Access-Control-Allow-Origin", "*");
	c.res.headers.set(
		"Access-Control-Allow-Methods",
		"GET, POST, DELETE, OPTIONS",
	);
	c.res.headers.set(
		"Access-Control-Allow-Headers",
		"Content-Type, Authorization",
	);

	// Security headers
	c.res.headers.set("X-Content-Type-Options", "nosniff");
	c.res.headers.set("X-Frame-Options", "DENY");
	c.res.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
	c.res.headers.set(
		"Permissions-Policy",
		"camera=(), microphone=(), geolocation=()",
	);
});

// Error handling middleware
app.onError((err, c) => {
	console.error("Unhandled error:", err);
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
