/**
 * FatSecret OAuth Routes
 *
 * Handles the OAuth 1.0a flow for FatSecret API authentication.
 *
 * Two flows supported:
 * 1. Simplified (cookie-based): /oauth/connect → /oauth/callback (uses existing session from setup page)
 * 2. Legacy (API-based): /oauth/setup → /oauth/complete (for programmatic access)
 */

import { Hono } from "hono";
import { FatSecretClient } from "../lib/client.js";
import {
	getSession,
	storeSession,
	storeOAuthState,
	getOAuthState,
	generateSessionToken,
} from "../lib/token-storage.js";
import { getSessionCookie } from "../lib/transforms.js";
import { safeLogError, safeErrorMessage } from "../lib/errors.js";
import {
	renderVerifierForm,
	renderOAuthSuccess,
	renderOAuthError,
} from "../views/oauth-callback.js";
import type { SessionData, OAuthState } from "../lib/schemas.js";
import type { AppEnv } from "../app.js";
import {
	OAUTH_STATE_TTL_SECONDS,
	MAX_TOKEN_LENGTH,
	MAX_CREDENTIAL_LENGTH,
	MAX_CALLBACK_URL_LENGTH,
} from "../lib/constants.js";

interface TokenExchangeResult {
	sessionToken: string;
	sessionData: SessionData;
	userId?: string;
}

async function exchangeOAuthTokens(
	kv: KVNamespace,
	encryptionKey: string,
	state: string,
	verifier: string,
): Promise<TokenExchangeResult> {
	const oauthState = await getOAuthState(kv, encryptionKey, state);
	if (!oauthState) {
		throw new Error("Invalid or expired state token. Please start the OAuth flow again.");
	}

	const existingSession = await getSession(kv, encryptionKey, oauthState.sessionToken);
	if (!existingSession) {
		throw new Error("Session expired. Please start the setup process again.");
	}

	const client = new FatSecretClient({
		clientId: existingSession.clientId,
		clientSecret: existingSession.clientSecret,
		consumerSecret: existingSession.consumerSecret,
	});

	const accessTokenResponse = await client.getAccessToken(
		oauthState.requestToken,
		oauthState.requestTokenSecret,
		verifier,
	);

	const sessionData: SessionData = {
		...existingSession,
		accessToken: accessTokenResponse.oauth_token,
		accessTokenSecret: accessTokenResponse.oauth_token_secret,
		userId: accessTokenResponse.user_id,
	};

	await storeSession(kv, encryptionKey, oauthState.sessionToken, sessionData);

	return {
		sessionToken: oauthState.sessionToken,
		sessionData,
		userId: accessTokenResponse.user_id,
	};
}

const oauthRoutes = new Hono<AppEnv>();

// ============================================================================
// Simplified Flow (Cookie-based) - For web UI
// ============================================================================

/**
 * GET /oauth/connect
 * Create a FatSecret profile using the Profile API (two-legged OAuth).
 * No browser login required — tokens are returned immediately.
 */
oauthRoutes.get("/oauth/connect", async (c) => {
	try {
		// Get session token from cookie
		const sessionToken = getSessionCookie(c.req.header("Cookie"));

		if (!sessionToken) {
			return c.redirect("/setup?error=no_session");
		}

		// Get session data
		const session = await getSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken);

		if (!session) {
			return c.redirect("/setup?error=invalid_session");
		}

		// Create client with stored credentials
		const client = new FatSecretClient({
			clientId: session.clientId,
			clientSecret: session.clientSecret,
			consumerSecret: session.consumerSecret,
		});

		// Create a profile via the Profile API (two-legged OAuth, no login needed)
		const profileId = session.profileId || `mcp-${crypto.randomUUID()}`;
		let profileAuth: { authToken: string; authSecret: string };

		try {
			profileAuth = await client.profileCreate(profileId);
		} catch (error) {
			// Profile may already exist — try getting existing auth tokens
			if (error instanceof Error && error.message.includes("already exists")) {
				profileAuth = await client.profileGetAuth(profileId);
			} else {
				throw error;
			}
		}

		// Update session with profile auth tokens
		const sessionData: SessionData = {
			...session,
			profileId,
			accessToken: profileAuth.authToken,
			accessTokenSecret: profileAuth.authSecret,
		};

		await storeSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken, sessionData);

		return c.redirect("/setup?success=connected");
	} catch (error) {
		safeLogError("Profile creation error", error);
		const message = safeErrorMessage(error, "oauth_error");
		return c.redirect(`/setup?error=oauth_failed&message=${message}`);
	}
});

/**
 * GET /oauth/connect-account
 * Start three-legged OAuth 1.0a flow to connect an existing fatsecret.com account.
 * Redirects user to FatSecret authorization page for login.
 */
oauthRoutes.get("/oauth/connect-account", async (c) => {
	try {
		// Get session token from cookie
		const sessionToken = getSessionCookie(c.req.header("Cookie"));

		if (!sessionToken) {
			return c.redirect("/setup?error=no_session");
		}

		// Get session data
		const session = await getSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken);

		if (!session) {
			return c.redirect("/setup?error=invalid_session");
		}

		// Create client with stored credentials
		const client = new FatSecretClient({
			clientId: session.clientId,
			clientSecret: session.clientSecret,
			consumerSecret: session.consumerSecret,
		});

		// Generate state and store it
		const state = generateSessionToken();
		const origin = new URL(c.req.url).origin;
		const callbackUrl = `${origin}/oauth/callback`;

		// Get request token with real callback URL
		const tokenResponse = await client.getRequestToken(callbackUrl);

		// Store OAuth state with reference to session token
		const oauthState: OAuthState = {
			sessionToken,
			requestToken: tokenResponse.oauth_token,
			requestTokenSecret: tokenResponse.oauth_token_secret,
			createdAt: Date.now(),
		};

		await storeOAuthState(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, state, oauthState);

		// Store state in a cookie so callback can find it (avoids query param issues)
		c.header(
			"Set-Cookie",
			`oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${OAUTH_STATE_TTL_SECONDS}`,
		);

		// Redirect to FatSecret authorization page
		const authUrl = client.getAuthorizationUrl(tokenResponse.oauth_token);
		return c.redirect(authUrl);
	} catch (error) {
		safeLogError("OAuth connect error", error);
		const message = safeErrorMessage(error, "oauth_error");
		return c.redirect(`/setup?error=oauth_failed&message=${message}`);
	}
});

// ============================================================================
// Legacy Flow (API-based) - For programmatic access
// ============================================================================

/**
 * POST /oauth/setup
 * Store user's FatSecret API credentials and start OAuth flow
 */
oauthRoutes.post("/oauth/setup", async (c) => {
	try {
		const body = await c.req.json();
		const { clientId, clientSecret, callbackUrl } = body;

		if (!clientId || !clientSecret) {
			return c.json(
				{
					error: "missing_credentials",
					message: "Both clientId and clientSecret are required",
				},
				400,
			);
		}

		if (
			typeof clientId !== "string" ||
			clientId.length > MAX_CREDENTIAL_LENGTH ||
			typeof clientSecret !== "string" ||
			clientSecret.length > MAX_CREDENTIAL_LENGTH ||
			(callbackUrl &&
				(typeof callbackUrl !== "string" || callbackUrl.length > MAX_CALLBACK_URL_LENGTH))
		) {
			return c.json({ error: "invalid_input", message: "Invalid input" }, 400);
		}

		// Create client with provided credentials
		const client = new FatSecretClient({ clientId, clientSecret });

		// Get request token from FatSecret
		const origin = new URL(c.req.url).origin;
		let callback = `${origin}/oauth/callback`;
		if (callbackUrl) {
			try {
				if (new URL(callbackUrl).origin === origin) {
					callback = callbackUrl;
				}
			} catch {
				// Malformed URL — use default callback
			}
		}
		const tokenResponse = await client.getRequestToken(callback);

		// Generate a session token and store credentials first
		const sessionToken = generateSessionToken();
		const sessionData: SessionData = {
			clientId,
			clientSecret,
			createdAt: Date.now(),
		};
		await storeSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken, sessionData);

		// Generate a state token to track this OAuth flow
		const state = generateSessionToken();

		// Store OAuth state temporarily (10 minutes)
		const oauthState: OAuthState = {
			sessionToken,
			requestToken: tokenResponse.oauth_token,
			requestTokenSecret: tokenResponse.oauth_token_secret,
			createdAt: Date.now(),
		};

		await storeOAuthState(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, state, oauthState);

		// Return authorization URL
		const authorizationUrl = client.getAuthorizationUrl(tokenResponse.oauth_token);

		return c.json({
			success: true,
			state,
			authorizationUrl,
			message:
				"Visit the authorization URL to grant access, then complete the flow with /oauth/callback",
		});
	} catch (error) {
		safeLogError("OAuth setup error", error);
		return c.json(
			{
				error: "oauth_setup_failed",
				message: "Failed to start OAuth flow",
			},
			500,
		);
	}
});

/**
 * GET /oauth/callback
 * Handle OAuth callback from FatSecret
 */
oauthRoutes.get("/oauth/callback", async (c) => {
	try {
		const { oauth_verifier } = c.req.query();
		// Read state from query param (legacy) or cookie (three-legged web flow)
		const state =
			c.req.query("state") || c.req.header("Cookie")?.match(/oauth_state=([^;]+)/)?.[1];

		if (oauth_verifier && oauth_verifier.length > MAX_TOKEN_LENGTH) {
			return c.json({ error: "invalid_input", message: "Invalid input" }, 400);
		}

		if (!oauth_verifier) {
			return c.html(renderVerifierForm());
		}

		if (!state) {
			return c.json(
				{
					error: "missing_state",
					message: "State token is required",
				},
				400,
			);
		}

		if (state.length > MAX_TOKEN_LENGTH) {
			return c.json({ error: "invalid_input", message: "Invalid input" }, 400);
		}

		const result = await exchangeOAuthTokens(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			state,
			oauth_verifier,
		);

		// Clear the oauth_state cookie now that it's been consumed
		c.header("Set-Cookie", "oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");

		// Check if this came from the cookie-based flow (redirect to setup page)
		const isWebFlow = c.req.header("Cookie")?.includes("fatsecret_session=");

		if (isWebFlow) {
			return c.redirect("/setup?success=connected");
		}

		// Return success HTML for legacy flow
		c.header("Cache-Control", "no-store");
		return c.html(
			renderOAuthSuccess({
				sessionToken: result.sessionToken,
				origin: new URL(c.req.url).origin,
				userId: result.userId || "N/A",
			}),
		);
	} catch (error) {
		safeLogError("OAuth callback error", error);
		return c.html(renderOAuthError(), 500);
	}
});

/**
 * POST /oauth/complete
 * Alternative endpoint to complete OAuth flow via API (not browser)
 */
oauthRoutes.post("/oauth/complete", async (c) => {
	try {
		const body = await c.req.json();
		const { state, verifier } = body;

		if (!state || !verifier) {
			return c.json(
				{
					error: "missing_params",
					message: "Both state and verifier are required",
				},
				400,
			);
		}

		if (
			typeof state !== "string" ||
			state.length > MAX_TOKEN_LENGTH ||
			typeof verifier !== "string" ||
			verifier.length > MAX_TOKEN_LENGTH
		) {
			return c.json({ error: "invalid_input", message: "Invalid input" }, 400);
		}

		const result = await exchangeOAuthTokens(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			state,
			verifier,
		);

		return c.json({
			success: true,
			sessionToken: result.sessionToken,
			userId: result.userId,
			message: "Authentication successful. Use the sessionToken as a Bearer token.",
		});
	} catch (error) {
		safeLogError("OAuth complete error", error);
		const message = error instanceof Error ? error.message : "Failed to complete OAuth flow";
		return c.json(
			{
				error: "oauth_complete_failed",
				message,
			},
			400,
		);
	}
});

export default oauthRoutes;
