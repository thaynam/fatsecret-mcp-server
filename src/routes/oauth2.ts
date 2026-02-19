/**
 * OAuth 2.0 Authorization Server Routes
 *
 * Implements the OAuth 2.0 endpoints required for Claude.ai Custom Connectors:
 * - Authorization Server Metadata (RFC 8414)
 * - Protected Resource Metadata (RFC 9728)
 * - Dynamic Client Registration (RFC 7591)
 * - Authorization Endpoint (with PKCE)
 * - Token Endpoint
 */

import { Hono } from "hono";
import {
	generateSessionToken,
	storeSession,
	getSession,
	maskSecret,
} from "../lib/token-storage.js";
import { getSessionCookie } from "../lib/transforms.js";
import { renderAuthorizePage } from "../views/authorize.js";
import {
	storeOAuth2Client,
	getOAuth2Client,
	storeAuthorizationCode,
	getAuthorizationCode,
} from "../lib/oauth2-storage.js";
import { FatSecretClient } from "../lib/client.js";
import { safeLogError } from "../lib/errors.js";
import type { SessionData } from "../lib/schemas.js";
import type { AppEnv } from "../app.js";
import {
	SESSION_TTL_SECONDS,
	MAX_CREDENTIAL_LENGTH,
	MAX_REDIRECT_URI_LENGTH,
	MAX_REDIRECT_URIS,
} from "../lib/constants.js";

const oauth2Routes = new Hono<AppEnv>();

// ============================================================================
// Helpers
// ============================================================================

/** SHA-256 hash a string and return hex */
async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const hash = await crypto.subtle.digest("SHA-256", data);
	return Array.from(new Uint8Array(hash))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/** Verify PKCE code_verifier against stored code_challenge (S256) with constant-time comparison */
async function verifyPKCE(codeVerifier: string, codeChallenge: string): Promise<boolean> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
	const computed = btoa(String.fromCharCode(...new Uint8Array(digest)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
	const a = new TextEncoder().encode(computed);
	const b = new TextEncoder().encode(codeChallenge);
	if (a.byteLength !== b.byteLength) return false;
	return crypto.subtle.timingSafeEqual(a, b);
}

/** Build the origin URL from a request */
function getOrigin(c: { req: { url: string } }): string {
	return new URL(c.req.url).origin;
}

// ============================================================================
// Metadata Endpoints
// ============================================================================

/**
 * GET /.well-known/oauth-authorization-server
 * RFC 8414 - Authorization Server Metadata
 */
oauth2Routes.get("/.well-known/oauth-authorization-server", (c) => {
	const origin = getOrigin(c);
	return c.json({
		issuer: origin,
		authorization_endpoint: `${origin}/oauth2/authorize`,
		token_endpoint: `${origin}/oauth2/token`,
		registration_endpoint: `${origin}/oauth2/register`,
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		token_endpoint_auth_methods_supported: ["client_secret_post"],
		code_challenge_methods_supported: ["S256"],
		scopes_supported: ["mcp"],
	});
});

/**
 * GET /.well-known/oauth-protected-resource/mcp
 * RFC 9728 - Protected Resource Metadata
 */
oauth2Routes.get("/.well-known/oauth-protected-resource/mcp", (c) => {
	const origin = getOrigin(c);
	return c.json({
		resource: `${origin}/mcp`,
		authorization_servers: [origin],
		scopes_supported: ["mcp"],
		bearer_methods_supported: ["header"],
	});
});

// ============================================================================
// Dynamic Client Registration (RFC 7591)
// ============================================================================

/**
 * POST /oauth2/register
 * Register a new OAuth 2.0 client (used by Claude.ai)
 */
oauth2Routes.post("/oauth2/register", async (c) => {
	try {
		const body = await c.req.json();
		const redirectUris: string[] = body.redirect_uris;

		if (!redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
			return c.json(
				{
					error: "invalid_client_metadata",
					error_description: "redirect_uris is required",
				},
				400,
			);
		}

		if (redirectUris.length > MAX_REDIRECT_URIS) {
			return c.json(
				{
					error: "invalid_client_metadata",
					error_description: `Too many redirect URIs (max ${MAX_REDIRECT_URIS})`,
				},
				400,
			);
		}

		// Validate redirect URIs are HTTPS (allow localhost for development)
		for (const uri of redirectUris) {
			if (typeof uri !== "string" || uri.length > MAX_REDIRECT_URI_LENGTH) {
				return c.json(
					{
						error: "invalid_client_metadata",
						error_description: "redirect_uri too long",
					},
					400,
				);
			}
			try {
				const parsed = new URL(uri);
				if (
					parsed.protocol !== "https:" &&
					parsed.hostname !== "localhost" &&
					parsed.hostname !== "127.0.0.1"
				) {
					return c.json(
						{
							error: "invalid_client_metadata",
							error_description: "redirect_uris must use HTTPS",
						},
						400,
					);
				}
			} catch {
				return c.json(
					{
						error: "invalid_client_metadata",
						error_description: "Invalid redirect_uri",
					},
					400,
				);
			}
		}

		// Validate client_name length
		const clientName =
			typeof body.client_name === "string" ? body.client_name.slice(0, 200) : undefined;

		// Generate client credentials
		const clientId = generateSessionToken();
		const clientSecret = generateSessionToken();
		const clientSecretHash = await sha256Hex(clientSecret);

		// Store client (hashed secret)
		await storeOAuth2Client(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, clientId, {
			clientId,
			clientSecretHash,
			redirectUris,
			clientName,
			grantTypes: ["authorization_code"],
			responseTypes: ["code"],
			createdAt: Date.now(),
		});

		// Return client credentials (plaintext secret only returned once)
		c.header("Cache-Control", "no-store");
		c.header("Pragma", "no-cache");
		return c.json(
			{
				client_id: clientId,
				client_secret: clientSecret,
				redirect_uris: redirectUris,
				client_name: clientName,
				token_endpoint_auth_method: "client_secret_post",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			},
			201,
		);
	} catch (error) {
		safeLogError("DCR error", error);
		return c.json({ error: "server_error", error_description: "Registration failed" }, 500);
	}
});

// ============================================================================
// Authorization Endpoint
// ============================================================================

/**
 * GET /oauth2/authorize
 * Renders the authorization page (consent or credential entry)
 */
oauth2Routes.get("/oauth2/authorize", async (c) => {
	const {
		response_type,
		client_id,
		redirect_uri,
		state,
		code_challenge,
		code_challenge_method,
		scope,
	} = c.req.query();

	// Validate required params
	if (response_type !== "code") {
		return c.json(
			{
				error: "unsupported_response_type",
				error_description: "Only response_type=code is supported",
			},
			400,
		);
	}

	if (!client_id || !redirect_uri || !code_challenge || !state) {
		return c.json(
			{
				error: "invalid_request",
				error_description:
					"Missing required parameters: client_id, redirect_uri, code_challenge, state",
			},
			400,
		);
	}

	if (code_challenge_method && code_challenge_method !== "S256") {
		return c.json(
			{
				error: "invalid_request",
				error_description: "Only code_challenge_method=S256 is supported",
			},
			400,
		);
	}

	// Verify client exists
	const client = await getOAuth2Client(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, client_id);
	if (!client) {
		return c.json({ error: "invalid_client", error_description: "Unknown client_id" }, 400);
	}

	// Verify redirect_uri matches registered URIs
	if (!client.redirectUris.includes(redirect_uri)) {
		return c.json(
			{
				error: "invalid_request",
				error_description: "redirect_uri does not match registered URIs",
			},
			400,
		);
	}

	// Check for existing session
	const sessionToken = getSessionCookie(c.req.header("Cookie"));
	let session: SessionData | null = null;
	if (sessionToken) {
		session = await getSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken);
	}

	const hasSession = !!(session?.clientId && session?.accessToken);

	c.header("Cache-Control", "no-store");
	return c.html(
		renderAuthorizePage({
			clientName: client.clientName,
			hasSession,
			maskedClientId: session?.clientId ? maskSecret(session.clientId) : undefined,
			clientId: client_id,
			redirectUri: redirect_uri,
			state,
			codeChallenge: code_challenge,
			codeChallengeMethod: code_challenge_method || "S256",
			scope: scope || "mcp",
		}),
	);
});

/**
 * POST /oauth2/authorize
 * Processes consent or credential form submission
 */
oauth2Routes.post("/oauth2/authorize", async (c) => {
	const body = await c.req.parseBody();
	const action = body.action as string;
	const clientId = body.client_id as string;
	const redirectUri = body.redirect_uri as string;
	const state = body.state as string;
	const codeChallenge = body.code_challenge as string;
	const codeChallengeMethod = body.code_challenge_method as string;
	const scope = (body.scope as string) || "mcp";

	// Verify client
	const client = await getOAuth2Client(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, clientId);
	if (!client || !client.redirectUris.includes(redirectUri)) {
		return c.json({ error: "invalid_client" }, 400);
	}

	// Handle deny
	if (action === "deny") {
		const denyUrl = new URL(redirectUri);
		denyUrl.searchParams.set("error", "access_denied");
		if (state) denyUrl.searchParams.set("state", state);
		return c.redirect(denyUrl.toString());
	}

	// Handle consent (existing session)
	if (action === "allow") {
		const sessionToken = getSessionCookie(c.req.header("Cookie"));

		if (!sessionToken) {
			return c.html(
				renderAuthorizePage({
					clientName: client.clientName,
					hasSession: false,
					error: "Session expired. Please enter your credentials.",
					clientId,
					redirectUri,
					state,
					codeChallenge,
					codeChallengeMethod,
					scope,
				}),
			);
		}

		const session = await getSession(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, sessionToken);

		if (!session?.accessToken) {
			return c.html(
				renderAuthorizePage({
					clientName: client.clientName,
					hasSession: false,
					error: "Session expired. Please enter your credentials.",
					clientId,
					redirectUri,
					state,
					codeChallenge,
					codeChallengeMethod,
					scope,
				}),
			);
		}

		// Issue authorization code
		const code = generateSessionToken();
		await storeAuthorizationCode(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, code, {
			clientId,
			redirectUri,
			codeChallenge,
			sessionToken,
			scope,
			createdAt: Date.now(),
		});

		const callbackUrl = new URL(redirectUri);
		callbackUrl.searchParams.set("code", code);
		if (state) callbackUrl.searchParams.set("state", state);
		return c.redirect(callbackUrl.toString());
	}

	// Handle credentials (new user)
	if (action === "credentials") {
		const fsClientId = body.fs_client_id as string;
		const fsClientSecret = body.fs_client_secret as string;
		const fsConsumerSecret = body.fs_consumer_secret as string;

		if (!fsClientId || !fsClientSecret || !fsConsumerSecret) {
			return c.html(
				renderAuthorizePage({
					clientName: client.clientName,
					hasSession: false,
					error: "All credential fields are required.",
					clientId,
					redirectUri,
					state,
					codeChallenge,
					codeChallengeMethod,
					scope,
				}),
			);
		}

		if (
			fsClientId.length > MAX_CREDENTIAL_LENGTH ||
			fsClientSecret.length > MAX_CREDENTIAL_LENGTH ||
			fsConsumerSecret.length > MAX_CREDENTIAL_LENGTH
		) {
			return c.html(
				renderAuthorizePage({
					clientName: client.clientName,
					hasSession: false,
					error: "Credential values are too long.",
					clientId,
					redirectUri,
					state,
					codeChallenge,
					codeChallengeMethod,
					scope,
				}),
			);
		}

		try {
			// Validate credentials
			const fsClient = new FatSecretClient({
				clientId: fsClientId,
				clientSecret: fsClientSecret,
				consumerSecret: fsConsumerSecret,
			});
			const valid = await fsClient.validateCredentials();
			if (!valid) {
				return c.html(
					renderAuthorizePage({
						clientName: client.clientName,
						hasSession: false,
						error: "Invalid FatSecret credentials. Please check your Client ID and Client Secret.",
						clientId,
						redirectUri,
						state,
						codeChallenge,
						codeChallengeMethod,
						scope,
					}),
				);
			}

			// Create profile via Profile API
			const profileId = `mcp-${crypto.randomUUID()}`;
			const profileAuth = await fsClient.profileCreate(profileId);

			// Create session
			const sessionToken = generateSessionToken();
			const sessionData: SessionData = {
				clientId: fsClientId,
				clientSecret: fsClientSecret,
				consumerSecret: fsConsumerSecret,
				profileId,
				accessToken: profileAuth.authToken,
				accessTokenSecret: profileAuth.authSecret,
				createdAt: Date.now(),
			};

			await storeSession(
				c.env.OAUTH_KV,
				c.env.COOKIE_ENCRYPTION_KEY,
				sessionToken,
				sessionData,
			);

			// Issue authorization code
			const code = generateSessionToken();
			await storeAuthorizationCode(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, code, {
				clientId,
				redirectUri,
				codeChallenge,
				sessionToken,
				scope,
				createdAt: Date.now(),
			});

			// Set session cookie for future use
			c.header(
				"Set-Cookie",
				`fatsecret_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${SESSION_TTL_SECONDS}`,
			);

			const callbackUrl = new URL(redirectUri);
			callbackUrl.searchParams.set("code", code);
			if (state) callbackUrl.searchParams.set("state", state);
			return c.redirect(callbackUrl.toString());
		} catch (error) {
			safeLogError("OAuth2 authorize error", error);
			return c.html(
				renderAuthorizePage({
					clientName: client.clientName,
					hasSession: false,
					error: "Failed to connect. Please check your credentials and try again.",
					clientId,
					redirectUri,
					state,
					codeChallenge,
					codeChallengeMethod,
					scope,
				}),
			);
		}
	}

	return c.json({ error: "invalid_request" }, 400);
});

// ============================================================================
// Token Endpoint
// ============================================================================

/**
 * POST /oauth2/token
 * Exchange authorization code for access token (with PKCE verification)
 */
oauth2Routes.post("/oauth2/token", async (c) => {
	const body = await c.req.parseBody();
	const grantType = body.grant_type as string;
	const code = body.code as string;
	const redirectUri = body.redirect_uri as string;
	const clientId = body.client_id as string;
	const clientSecret = body.client_secret as string;
	const codeVerifier = body.code_verifier as string;

	if (grantType !== "authorization_code") {
		return c.json(
			{
				error: "unsupported_grant_type",
				error_description: "Only authorization_code is supported",
			},
			400,
		);
	}

	if (!code || !clientId || !clientSecret || !codeVerifier) {
		return c.json(
			{
				error: "invalid_request",
				error_description: "Missing required parameters",
			},
			400,
		);
	}

	// Verify client credentials
	const client = await getOAuth2Client(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, clientId);
	if (!client) {
		return c.json({ error: "invalid_client", error_description: "Unknown client" }, 401);
	}

	const secretHash = await sha256Hex(clientSecret);
	const encoder = new TextEncoder();
	const hashA = encoder.encode(secretHash);
	const hashB = encoder.encode(client.clientSecretHash);
	if (hashA.byteLength !== hashB.byteLength || !crypto.subtle.timingSafeEqual(hashA, hashB)) {
		return c.json(
			{
				error: "invalid_client",
				error_description: "Invalid client credentials",
			},
			401,
		);
	}

	// Retrieve and consume authorization code (single-use)
	const codeData = await getAuthorizationCode(c.env.OAUTH_KV, c.env.COOKIE_ENCRYPTION_KEY, code);
	if (!codeData) {
		return c.json(
			{
				error: "invalid_grant",
				error_description: "Authorization code is invalid or expired",
			},
			400,
		);
	}

	// Verify client_id and redirect_uri match
	if (codeData.clientId !== clientId) {
		return c.json({ error: "invalid_grant", error_description: "Client mismatch" }, 400);
	}
	if (!redirectUri || codeData.redirectUri !== redirectUri) {
		return c.json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, 400);
	}

	// PKCE verification
	const pkceValid = await verifyPKCE(codeVerifier, codeData.codeChallenge);
	if (!pkceValid) {
		return c.json(
			{ error: "invalid_grant", error_description: "PKCE verification failed" },
			400,
		);
	}

	// The session token IS the access token
	c.header("Cache-Control", "no-store");
	c.header("Pragma", "no-cache");
	return c.json({
		access_token: codeData.sessionToken,
		token_type: "bearer",
		scope: codeData.scope,
	});
});

export default oauth2Routes;
