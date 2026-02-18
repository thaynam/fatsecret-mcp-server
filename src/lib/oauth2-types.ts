/**
 * OAuth 2.0 Authorization Server Types
 *
 * Types for Dynamic Client Registration and authorization code flow.
 */

/** Data stored for a dynamically registered OAuth 2.0 client */
export interface OAuth2ClientData {
	clientId: string;
	clientSecretHash: string; // SHA-256 hex hash (plaintext returned once at registration)
	redirectUris: string[];
	clientName?: string;
	grantTypes: string[];
	responseTypes: string[];
	createdAt: number;
}

/** Data stored alongside an authorization code */
export interface AuthorizationCodeData {
	clientId: string;
	redirectUri: string;
	codeChallenge: string; // base64url-encoded SHA-256 from PKCE
	sessionToken: string; // becomes the access_token
	scope: string;
	createdAt: number;
}
