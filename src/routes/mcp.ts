/**
 * MCP Routes
 *
 * Handles MCP protocol endpoints with bearer authentication.
 */

import { Hono } from "hono";
import { bearerAuth } from "../middleware/auth.js";
import type { SessionData } from "../lib/schemas.js";

interface Variables {
	sessionToken: string;
	sessionData: SessionData;
}

// Create MCP routes function that accepts mcpHandlers
export function createMcpRoutes(mcpHandlers: any) {
	const mcpRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

	// Streamable HTTP endpoint (matches /mcp and /mcp/*)
	mcpRoutes.all("/mcp/*", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");

		// Create ExecutionContext with props
		const ctx = c.executionCtx as any;
		ctx.props = {
			sessionToken,
			baseUrl: new URL(c.req.url).origin,
		};

		// Forward request to MCP handler
		const response = await mcpHandlers.streamableHTTP.fetch(
			c.req.raw,
			c.env,
			ctx,
		);

		return response;
	});

	// Also handle /mcp without trailing path for initialization
	mcpRoutes.all("/mcp", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");

		const ctx = c.executionCtx as any;
		ctx.props = {
			sessionToken,
			baseUrl: new URL(c.req.url).origin,
		};

		const response = await mcpHandlers.streamableHTTP.fetch(
			c.req.raw,
			c.env,
			ctx,
		);

		return response;
	});

	// Legacy SSE endpoint for backward compatibility (matches /sse and /sse/*)
	mcpRoutes.all("/sse/*", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");

		const ctx = c.executionCtx as any;
		ctx.props = {
			sessionToken,
			baseUrl: new URL(c.req.url).origin,
		};

		return await mcpHandlers.sse.fetch(c.req.raw, c.env, ctx);
	});

	// Also handle /sse without trailing path
	mcpRoutes.all("/sse", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");

		const ctx = c.executionCtx as any;
		ctx.props = {
			sessionToken,
			baseUrl: new URL(c.req.url).origin,
		};

		return await mcpHandlers.sse.fetch(c.req.raw, c.env, ctx);
	});

	return mcpRoutes;
}
