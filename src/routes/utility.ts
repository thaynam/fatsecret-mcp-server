/**
 * Utility Routes
 *
 * Health check, home page, setup page, and credential management.
 */

import { Hono } from "hono";
import { FatSecretClient } from "../lib/client.js";
import {
	getSession,
	storeSession,
	deleteSession,
	generateSessionToken,
	maskSecret,
} from "../lib/token-storage.js";
import { escapeHtml, getSessionCookie } from "../lib/transforms.js";
import { safeLogError } from "../lib/errors.js";
import { renderHomePage } from "../views/home.js";
import { renderSetupPage } from "../views/setup.js";
import type { SessionData } from "../lib/schemas.js";
import type { AppEnv } from "../app.js";
import { SESSION_TTL_SECONDS, MAX_CREDENTIAL_LENGTH } from "../lib/constants.js";

const utilityRoutes = new Hono<AppEnv>();

/**
 * GET /health
 */
utilityRoutes.get("/health", (c) => {
	return c.json({ status: "ok" });
});

/**
 * GET / - Home page
 */
utilityRoutes.get("/", (c) => {
	return c.html(renderHomePage());
});

/**
 * GET /setup - Setup page
 */
utilityRoutes.get("/setup", async (c) => {
	const sessionToken = getSessionCookie(c.req.header("Cookie"));

	// Get query params for error/success messages
	const url = new URL(c.req.url);
	const errorType = url.searchParams.get("error");
	const errorMessage = url.searchParams.get("message");
	const success = url.searchParams.get("success");

	let session: SessionData | null = null;
	if (sessionToken) {
		session = await getSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken);
	}

	const hasCredentials = !!session;
	const hasUserAuth = !!(session?.accessToken && session?.accessTokenSecret);
	const baseUrl = url.origin;

	// Build alert message HTML
	let alertHtml = "";
	if (errorType) {
		const msg = errorMessage
			? escapeHtml(decodeURIComponent(errorMessage))
			: getErrorMessage(errorType);
		alertHtml = `<div class="alert alert-error">${msg}</div>`;
	} else if (success === "connected") {
		alertHtml = `<div class="alert alert-success">FatSecret account connected successfully!</div>`;
	}

	function getErrorMessage(type: string): string {
		switch (type) {
			case "no_session":
				return "No session found. Please enter your credentials first.";
			case "invalid_session":
				return "Session expired. Please enter your credentials again.";
			case "oauth_failed":
				return "OAuth flow failed. Please try again.";
			default:
				return "An error occurred. Please try again.";
		}
	}

	c.header("Cache-Control", "no-store");
	return c.html(
		renderSetupPage({
			hasCredentials,
			hasUserAuth,
			sessionToken: sessionToken || null,
			baseUrl,
			maskedClientId: maskSecret(session?.clientId || ""),
			userId: session?.userId || "OK",
			alertHtml,
		}),
	);
});

/**
 * POST /api/save-credentials
 */
utilityRoutes.post("/api/save-credentials", async (c) => {
	try {
		const { clientId, clientSecret, consumerSecret } = await c.req.json();
		if (!clientId || !clientSecret) {
			return c.json({ error: "Client ID and Client Secret are required" }, 400);
		}

		if (
			typeof clientId !== "string" ||
			clientId.length > MAX_CREDENTIAL_LENGTH ||
			typeof clientSecret !== "string" ||
			clientSecret.length > MAX_CREDENTIAL_LENGTH ||
			(consumerSecret &&
				(typeof consumerSecret !== "string" ||
					consumerSecret.length > MAX_CREDENTIAL_LENGTH))
		) {
			return c.json({ error: "Invalid input" }, 400);
		}

		const client = new FatSecretClient({ clientId, clientSecret });
		if (!(await client.validateCredentials())) {
			return c.json(
				{ error: "Invalid OAuth 2.0 credentials (Client ID / Client Secret)" },
				400,
			);
		}

		const sessionToken = generateSessionToken();
		const sessionData: SessionData = {
			clientId,
			clientSecret,
			consumerSecret: consumerSecret || undefined,
			createdAt: Date.now(),
		};
		await storeSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken, sessionData);

		const response = c.json({ success: true, sessionToken });
		response.headers.set(
			"Set-Cookie",
			`fatsecret_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`,
		);
		return response;
	} catch (error) {
		safeLogError("Save credentials error", error);
		return c.json({ error: "Failed to save credentials" }, 500);
	}
});

/**
 * DELETE /api/delete-credentials
 */
utilityRoutes.delete("/api/delete-credentials", async (c) => {
	const sessionToken = getSessionCookie(c.req.header("Cookie"));
	if (sessionToken) await deleteSession(c.env.OAUTH_KV, sessionToken);
	const response = c.json({ success: true });
	response.headers.set(
		"Set-Cookie",
		"fatsecret_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
	);
	return response;
});

export default utilityRoutes;
