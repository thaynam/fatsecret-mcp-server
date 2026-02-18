/**
 * Bearer token authentication middleware
 *
 * Validates Authorization header and loads session data from KV.
 */

import { createMiddleware } from "hono/factory";
import { getSession } from "../lib/token-storage.js";
import type { Variables } from "../app.js";

/**
 * Bearer token authentication middleware
 * Validates Authorization header and stores session info in context
 */
export const bearerAuth = createMiddleware<{
	Bindings: Env;
	Variables: Variables;
}>(async (c, next) => {
	const authHeader = c.req.header("Authorization");

	const origin = new URL(c.req.url).origin;
	const resourceMetadataUrl = `${origin}/.well-known/oauth-protected-resource/mcp`;

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return c.json(
			{
				error: "unauthorized",
				message:
					"Authentication required. Please provide a valid Bearer token.",
			},
			401,
			{
				"WWW-Authenticate": `Bearer realm="${origin}/mcp", resource_metadata="${resourceMetadataUrl}"`,
			},
		);
	}

	const token = authHeader.substring(7); // Remove "Bearer " prefix

	// Load session from encrypted KV
	const sessionData = await getSession(
		c.env.OAUTH_KV,
		c.env.COOKIE_ENCRYPTION_KEY,
		token,
	);

	if (!sessionData) {
		return c.json(
			{
				error: "unauthorized",
				message: "Invalid or expired token. Please authenticate again.",
			},
			401,
			{
				"WWW-Authenticate": `Bearer realm="${origin}/mcp", resource_metadata="${resourceMetadataUrl}", error="invalid_token"`,
			},
		);
	}

	// Store session info in context variables
	c.set("sessionToken", token);
	c.set("sessionData", sessionData);

	await next();
});
