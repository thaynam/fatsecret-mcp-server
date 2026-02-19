/**
 * MCP Routes
 *
 * Handles MCP protocol endpoints with bearer authentication.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { bearerAuth } from "../middleware/auth.js";
import type { AppEnv } from "../app.js";

interface McpHandler {
	fetch: (req: Request, env: Env, ctx: ExecutionContext) => Promise<Response>;
}

export interface McpHandlers {
	streamableHTTP: McpHandler;
	sse: McpHandler;
}

function withProps(ctx: ExecutionContext, sessionToken: string, url: string): ExecutionContext {
	Object.defineProperty(ctx, "props", {
		value: { sessionToken, baseUrl: new URL(url).origin },
		writable: true,
		configurable: true,
	});
	return ctx;
}

function mcpHandler(handler: McpHandler) {
	return [
		bearerAuth,
		async (c: Context<AppEnv>) => {
			const sessionToken = c.get("sessionToken");
			if (!sessionToken) {
				return c.json({ error: "unauthorized" }, 401);
			}
			const ctx = withProps(c.executionCtx, sessionToken, c.req.url);
			return await handler.fetch(c.req.raw, c.env, ctx);
		},
	] as const;
}

export function createMcpRoutes(mcpHandlers: McpHandlers) {
	const mcpRoutes = new Hono<AppEnv>();

	mcpRoutes.all("/mcp/*", ...mcpHandler(mcpHandlers.streamableHTTP));
	mcpRoutes.all("/mcp", ...mcpHandler(mcpHandlers.streamableHTTP));
	mcpRoutes.all("/sse/*", ...mcpHandler(mcpHandlers.sse));
	mcpRoutes.all("/sse", ...mcpHandler(mcpHandlers.sse));

	return mcpRoutes;
}
