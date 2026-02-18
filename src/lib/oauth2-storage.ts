/**
 * OAuth 2.0 KV Storage Helpers
 *
 * Storage functions for OAuth 2.0 clients (DCR) and authorization codes.
 * Follows the same encryption patterns as token-storage.ts.
 */

import { encryptData, decryptData } from "./token-storage.js";
import type {
	OAuth2ClientData,
	AuthorizationCodeData,
} from "./oauth2-types.js";

const CLIENT_EXPIRATION = 90 * 24 * 60 * 60; // 90 days in seconds
const CODE_EXPIRATION = 10 * 60; // 10 minutes in seconds

/**
 * Store a registered OAuth 2.0 client in KV (encrypted)
 */
export async function storeOAuth2Client(
	kv: KVNamespace,
	encryptionKey: string,
	clientId: string,
	clientData: OAuth2ClientData,
): Promise<void> {
	const encrypted = await encryptData(
		JSON.stringify(clientData),
		encryptionKey,
	);
	await kv.put(`oauth2_client:${clientId}`, encrypted, {
		expirationTtl: CLIENT_EXPIRATION,
	});
}

/**
 * Retrieve a registered OAuth 2.0 client from KV (decrypted)
 */
export async function getOAuth2Client(
	kv: KVNamespace,
	encryptionKey: string,
	clientId: string,
): Promise<OAuth2ClientData | null> {
	const encrypted = await kv.get(`oauth2_client:${clientId}`);
	if (!encrypted) return null;
	try {
		const decrypted = await decryptData(encrypted, encryptionKey);
		return JSON.parse(decrypted) as OAuth2ClientData;
	} catch {
		return null;
	}
}

/**
 * Store an authorization code in KV (encrypted, single-use, 10-min TTL)
 */
export async function storeAuthorizationCode(
	kv: KVNamespace,
	encryptionKey: string,
	code: string,
	codeData: AuthorizationCodeData,
): Promise<void> {
	const encrypted = await encryptData(JSON.stringify(codeData), encryptionKey);
	await kv.put(`oauth2_code:${code}`, encrypted, {
		expirationTtl: CODE_EXPIRATION,
	});
}

/**
 * Retrieve an authorization code from KV (decrypted) and delete it (single-use)
 */
export async function getAuthorizationCode(
	kv: KVNamespace,
	encryptionKey: string,
	code: string,
): Promise<AuthorizationCodeData | null> {
	const kvKey = `oauth2_code:${code}`;
	const encrypted = await kv.get(kvKey);
	if (!encrypted) return null;
	// Single-use: delete immediately
	await kv.delete(kvKey);
	try {
		const decrypted = await decryptData(encrypted, encryptionKey);
		return JSON.parse(decrypted) as AuthorizationCodeData;
	} catch {
		return null;
	}
}
