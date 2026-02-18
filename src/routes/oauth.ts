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
import { escapeHtml } from "../lib/transforms.js";
import type { SessionData, OAuthState } from "../lib/schemas.js";

const oauthRoutes = new Hono<{ Bindings: Env }>();

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
		const sessionCookie = c.req.header("Cookie");
		const sessionToken = sessionCookie?.match(/fatsecret_session=([^;]+)/)?.[1];

		if (!sessionToken) {
			return c.redirect("/setup?error=no_session");
		}

		// Get session data
		const session = await getSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
		);

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

		await storeSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
			sessionData,
		);

		return c.redirect("/setup?success=connected");
	} catch (error) {
		console.error("Profile creation error:", error);
		let message = "Failed to create profile";
		try {
			const errorMsg = error instanceof Error ? error.message : "Unknown error";
			message = encodeURIComponent(
				errorMsg.substring(0, 200).replace(/[^\x20-\x7E]/g, ""),
			);
		} catch {
			message = "profile_error";
		}
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
		const sessionCookie = c.req.header("Cookie");
		const sessionToken = sessionCookie?.match(/fatsecret_session=([^;]+)/)?.[1];

		if (!sessionToken) {
			return c.redirect("/setup?error=no_session");
		}

		// Get session data
		const session = await getSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
		);

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

		await storeOAuthState(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			state,
			oauthState,
		);

		// Store state in a cookie so callback can find it (avoids query param issues)
		c.header(
			"Set-Cookie",
			`oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=600`,
		);

		// Redirect to FatSecret authorization page
		const authUrl = client.getAuthorizationUrl(tokenResponse.oauth_token);
		return c.redirect(authUrl);
	} catch (error) {
		console.error("OAuth connect error:", error);
		let message = "Failed to start OAuth";
		try {
			const errorMsg = error instanceof Error ? error.message : "Unknown error";
			message = encodeURIComponent(
				errorMsg.substring(0, 200).replace(/[^\x20-\x7E]/g, ""),
			);
		} catch {
			message = "OAuth_error";
		}
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

		// Create client with provided credentials
		const client = new FatSecretClient({ clientId, clientSecret });

		// Get request token from FatSecret
		const callback =
			callbackUrl || `${new URL(c.req.url).origin}/oauth/callback`;
		const tokenResponse = await client.getRequestToken(callback);

		// Generate a session token and store credentials first
		const sessionToken = generateSessionToken();
		const sessionData: SessionData = {
			clientId,
			clientSecret,
			createdAt: Date.now(),
		};
		await storeSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
			sessionData,
		);

		// Generate a state token to track this OAuth flow
		const state = generateSessionToken();

		// Store OAuth state temporarily (10 minutes)
		const oauthState: OAuthState = {
			sessionToken,
			requestToken: tokenResponse.oauth_token,
			requestTokenSecret: tokenResponse.oauth_token_secret,
			createdAt: Date.now(),
		};

		await storeOAuthState(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			state,
			oauthState,
		);

		// Return authorization URL
		const authorizationUrl = client.getAuthorizationUrl(
			tokenResponse.oauth_token,
		);

		return c.json({
			success: true,
			state,
			authorizationUrl,
			message:
				"Visit the authorization URL to grant access, then complete the flow with /oauth/callback",
		});
	} catch (error) {
		console.error("OAuth setup error:", error);
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
			c.req.query("state") ||
			c.req.header("Cookie")?.match(/oauth_state=([^;]+)/)?.[1];

		if (!oauth_verifier) {
			return c.html(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>FatSecret OAuth - Enter Verifier</title>
                    <style>
                        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
                        input, button { font-size: 16px; padding: 10px; margin: 5px 0; }
                        input { width: 100%; box-sizing: border-box; }
                        button { background: #007bff; color: white; border: none; cursor: pointer; }
                        button:hover { background: #0056b3; }
                    </style>
                </head>
                <body>
                    <h1>FatSecret OAuth</h1>
                    <p>Enter the verifier code from FatSecret:</p>
                    <form method="GET" action="/oauth/callback">
                        <input type="text" name="state" placeholder="State token from /oauth/setup" required>
                        <input type="text" name="oauth_verifier" placeholder="Verifier code" required>
                        <button type="submit">Complete Authentication</button>
                    </form>
                </body>
                </html>
            `);
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

		// Retrieve OAuth state
		const oauthState = await getOAuthState(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			state,
		);

		if (!oauthState) {
			return c.json(
				{
					error: "invalid_state",
					message:
						"Invalid or expired state token. Please start the OAuth flow again.",
				},
				400,
			);
		}

		// Get existing session to retrieve credentials
		const existingSession = await getSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			oauthState.sessionToken,
		);

		if (!existingSession) {
			return c.json(
				{
					error: "session_expired",
					message: "Session expired. Please start the setup process again.",
				},
				400,
			);
		}

		// Create client with stored credentials
		const client = new FatSecretClient({
			clientId: existingSession.clientId,
			clientSecret: existingSession.clientSecret,
			consumerSecret: existingSession.consumerSecret,
		});

		// Exchange for access token
		const accessTokenResponse = await client.getAccessToken(
			oauthState.requestToken,
			oauthState.requestTokenSecret,
			oauth_verifier,
		);

		// Update session with access tokens
		const sessionToken = oauthState.sessionToken;
		const sessionData: SessionData = {
			...existingSession,
			accessToken: accessTokenResponse.oauth_token,
			accessTokenSecret: accessTokenResponse.oauth_token_secret,
			userId: accessTokenResponse.user_id,
		};

		await storeSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
			sessionData,
		);

		// Check if this came from the cookie-based flow (redirect to setup page)
		const isWebFlow = c.req.header("Cookie")?.includes("fatsecret_session=");

		if (isWebFlow) {
			// Redirect back to setup page with success message
			return c.redirect("/setup?success=connected");
		}

		// Return success HTML for legacy flow
		c.header("Cache-Control", "no-store");
		return c.html(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>FatSecret OAuth - Success</title>
                <style>
                    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
                    .token { background: #f0f0f0; padding: 15px; border-radius: 5px; word-break: break-all; font-family: monospace; }
                    .copy-btn { margin-top: 10px; padding: 8px 16px; cursor: pointer; }
                </style>
            </head>
            <body>
                <h1>Authentication Successful!</h1>
                <p>Your FatSecret account is now connected. Use this token as a Bearer token in your MCP client:</p>
                <div class="token" id="token">${escapeHtml(sessionToken)}</div>
                <button class="copy-btn" onclick="navigator.clipboard.writeText('${escapeHtml(sessionToken)}')">Copy Token</button>
                <h2>MCP Configuration</h2>
                <p>Add this to your MCP client configuration:</p>
                <pre style="background: #f0f0f0; padding: 15px; border-radius: 5px; overflow-x: auto;">
{
  "mcpServers": {
    "fatsecret": {
      "url": "${new URL(c.req.url).origin}/mcp",
      "transport": {
        "type": "http",
        "headers": {
          "Authorization": "Bearer ${escapeHtml(sessionToken)}"
        }
      }
    }
  }
}</pre>
                <p><strong>User ID:</strong> ${escapeHtml(accessTokenResponse.user_id || "N/A")}</p>
            </body>
            </html>
        `);
	} catch (error) {
		console.error("OAuth callback error:", error);
		return c.html(
			`
            <!DOCTYPE html>
            <html>
            <head><title>OAuth Error</title></head>
            <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
                <h1>Authentication Failed</h1>
                <p>Authentication could not be completed. Please try again.</p>
                <p><a href="/">Try again</a></p>
            </body>
            </html>
        `,
			500,
		);
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

		// Retrieve OAuth state
		const oauthState = await getOAuthState(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			state,
		);

		if (!oauthState) {
			return c.json(
				{
					error: "invalid_state",
					message:
						"Invalid or expired state token. Please start the OAuth flow again.",
				},
				400,
			);
		}

		// Get existing session
		const existingSession = await getSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			oauthState.sessionToken,
		);

		if (!existingSession) {
			return c.json(
				{
					error: "session_expired",
					message: "Session expired. Please start the setup process again.",
				},
				400,
			);
		}

		// Create client with stored credentials
		const client = new FatSecretClient({
			clientId: existingSession.clientId,
			clientSecret: existingSession.clientSecret,
			consumerSecret: existingSession.consumerSecret,
		});

		// Exchange for access token
		const accessTokenResponse = await client.getAccessToken(
			oauthState.requestToken,
			oauthState.requestTokenSecret,
			verifier,
		);

		// Update session with access tokens
		const sessionToken = oauthState.sessionToken;
		const sessionData: SessionData = {
			...existingSession,
			accessToken: accessTokenResponse.oauth_token,
			accessTokenSecret: accessTokenResponse.oauth_token_secret,
			userId: accessTokenResponse.user_id,
		};

		await storeSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
			sessionData,
		);

		return c.json({
			success: true,
			sessionToken,
			userId: accessTokenResponse.user_id,
			message:
				"Authentication successful. Use the sessionToken as a Bearer token.",
		});
	} catch (error) {
		console.error("OAuth complete error:", error);
		return c.json(
			{
				error: "oauth_complete_failed",
				message: "Failed to complete OAuth flow",
			},
			500,
		);
	}
});

export default oauthRoutes;
