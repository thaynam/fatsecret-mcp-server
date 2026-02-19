/**
 * MCP Routes
 *
 * Handles MCP protocol endpoints with bearer authentication.
 */

import { Hono } from "hono";
import { bearerAuth } from "../middleware/auth.js";
import type { Variables } from "../app.js";

interface McpHandlers {
	streamableHTTP: {
		fetch: (req: Request, env: Env, ctx: ExecutionContext) => Promise<Response>;
	};
	sse: {
		fetch: (req: Request, env: Env, ctx: ExecutionContext) => Promise<Response>;
	};
}

function withProps(
	ctx: ExecutionContext,
	sessionToken: string,
	url: string,
): ExecutionContext {
	// ExecutionContext.props is readonly, so we assign via Object.defineProperty
	Object.defineProperty(ctx, "props", {
		value: { sessionToken, baseUrl: new URL(url).origin },
		writable: true,
		configurable: true,
	});
	return ctx;
}

// Create MCP routes function that accepts mcpHandlers
export function createMcpRoutes(mcpHandlers: McpHandlers) {
	const mcpRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

	// Streamable HTTP endpoint (matches /mcp and /mcp/*)
	mcpRoutes.all("/mcp/*", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");
		if (!sessionToken) {
			return c.json({ error: "unauthorized" }, 401);
		}
		const ctx = withProps(c.executionCtx, sessionToken, c.req.url);
		return await mcpHandlers.streamableHTTP.fetch(c.req.raw, c.env, ctx);
	});

	// Also handle /mcp without trailing path for initialization
	mcpRoutes.all("/mcp", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");
		if (!sessionToken) {
			return c.json({ error: "unauthorized" }, 401);
		}
		const ctx = withProps(c.executionCtx, sessionToken, c.req.url);
		return await mcpHandlers.streamableHTTP.fetch(c.req.raw, c.env, ctx);
	});

	// Legacy SSE endpoint for backward compatibility (matches /sse and /sse/*)
	mcpRoutes.all("/sse/*", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");
		if (!sessionToken) {
			return c.json({ error: "unauthorized" }, 401);
		}
		const ctx = withProps(c.executionCtx, sessionToken, c.req.url);
		return await mcpHandlers.sse.fetch(c.req.raw, c.env, ctx);
	});

	// Also handle /sse without trailing path
	mcpRoutes.all("/sse", bearerAuth, async (c) => {
		const sessionToken = c.get("sessionToken");
		if (!sessionToken) {
			return c.json({ error: "unauthorized" }, 401);
		}
		const ctx = withProps(c.executionCtx, sessionToken, c.req.url);
		return await mcpHandlers.sse.fetch(c.req.raw, c.env, ctx);
	});

	return mcpRoutes;
}
