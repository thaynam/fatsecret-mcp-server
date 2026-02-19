/**
 * Token Storage Module
 *
 * Provides secure storage and retrieval of user FatSecret OAuth tokens in Cloudflare KV.
 * All data is encrypted at rest using AES-GCM encryption.
 */

import type { SessionData, OAuthState } from "./schemas.js";
import { safeLogError } from "./errors.js";
import { SESSION_TTL_SECONDS, OAUTH_STATE_TTL_SECONDS } from "./constants.js";

/**
 * Converts a hex string to a Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
	if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
		throw new Error("Encryption key must be exactly 64 hex characters (32 bytes)");
	}
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
	}
	return bytes;
}

/**
 * Encrypts data using AES-GCM
 *
 * @param data - The plaintext data to encrypt
 * @param encryptionKeyHex - The encryption key as a hex string (64 chars / 32 bytes)
 * @returns Base64-encoded encrypted data with IV prepended
 */
export async function encryptData(data: string, encryptionKeyHex: string): Promise<string> {
	const keyBytes = hexToBytes(encryptionKeyHex);

	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		keyBytes,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt"],
	);

	// Generate a random IV (12 bytes is recommended for AES-GCM)
	const iv = crypto.getRandomValues(new Uint8Array(12));

	const encoder = new TextEncoder();
	const dataBytes = encoder.encode(data);

	const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, dataBytes);

	// Combine IV + encrypted data
	const combined = new Uint8Array(iv.length + encrypted.byteLength);
	combined.set(iv, 0);
	combined.set(new Uint8Array(encrypted), iv.length);

	return btoa(Array.from(combined, (b) => String.fromCharCode(b)).join(""));
}

/**
 * Decrypts data that was encrypted with encryptData
 *
 * @param encryptedBase64 - The encrypted data (base64-encoded, IV prepended)
 * @param encryptionKeyHex - The encryption key as a hex string (64 chars / 32 bytes)
 * @returns The decrypted plaintext data
 */
export async function decryptData(
	encryptedBase64: string,
	encryptionKeyHex: string,
): Promise<string> {
	const keyBytes = hexToBytes(encryptionKeyHex);

	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		keyBytes,
		{ name: "AES-GCM", length: 256 },
		false,
		["decrypt"],
	);

	const combined = Uint8Array.from(atob(encryptedBase64), (c) => c.charCodeAt(0));

	const iv = combined.slice(0, 12);
	const encrypted = combined.slice(12);

	const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, encrypted);

	const decoder = new TextDecoder();
	return decoder.decode(decrypted);
}

/**
 * Hash a value with SHA-256 for use as a KV key.
 * Prevents token enumeration if KV listing access is compromised.
 */
export async function kvKeyHash(value: string): Promise<string> {
	const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	return Array.from(new Uint8Array(hash))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/**
 * Generate a random session token
 */
export function generateSessionToken(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/**
 * Store a user session in KV (encrypted)
 *
 * @param kv - Cloudflare KV namespace
 * @param encryptionKey - Encryption key (hex string)
 * @param sessionToken - The session token
 * @param sessionData - The session data to store
 */
export async function storeSession(
	kv: KVNamespace,
	encryptionKey: string,
	sessionToken: string,
	sessionData: SessionData,
): Promise<void> {
	const encrypted = await encryptData(JSON.stringify(sessionData), encryptionKey);
	const kvKey = `session:${await kvKeyHash(sessionToken)}`;
	await kv.put(kvKey, encrypted, { expirationTtl: SESSION_TTL_SECONDS });
}

/**
 * Retrieve a user session from KV (decrypted)
 *
 * @param kv - Cloudflare KV namespace
 * @param encryptionKey - Encryption key (hex string)
 * @param sessionToken - The session token
 * @returns The decrypted session data, or null if not found
 */
export async function getSession(
	kv: KVNamespace,
	encryptionKey: string,
	sessionToken: string,
): Promise<SessionData | null> {
	const kvKey = `session:${await kvKeyHash(sessionToken)}`;
	const encrypted = await kv.get(kvKey);

	if (!encrypted) {
		return null;
	}

	try {
		const decrypted = await decryptData(encrypted, encryptionKey);
		return JSON.parse(decrypted) as SessionData;
	} catch (error) {
		safeLogError("Failed to decrypt session data", error);
		return null;
	}
}

/**
 * Delete a user session from KV
 *
 * @param kv - Cloudflare KV namespace
 * @param sessionToken - The session token
 */
export async function deleteSession(kv: KVNamespace, sessionToken: string): Promise<void> {
	const kvKey = `session:${await kvKeyHash(sessionToken)}`;
	await kv.delete(kvKey);
}

/**
 * Store temporary OAuth state during the OAuth flow
 *
 * @param kv - Cloudflare KV namespace
 * @param encryptionKey - Encryption key (hex string)
 * @param state - The OAuth state token
 * @param oauthState - The OAuth state data
 */
export async function storeOAuthState(
	kv: KVNamespace,
	encryptionKey: string,
	state: string,
	oauthState: OAuthState,
): Promise<void> {
	const encrypted = await encryptData(JSON.stringify(oauthState), encryptionKey);
	const kvKey = `oauth_state:${await kvKeyHash(state)}`;
	await kv.put(kvKey, encrypted, { expirationTtl: OAUTH_STATE_TTL_SECONDS });
}

/**
 * Retrieve OAuth state from KV (and delete it - single use)
 *
 * @param kv - Cloudflare KV namespace
 * @param encryptionKey - Encryption key (hex string)
 * @param state - The OAuth state token
 * @returns The OAuth state data, or null if not found/expired
 */
export async function getOAuthState(
	kv: KVNamespace,
	encryptionKey: string,
	state: string,
): Promise<OAuthState | null> {
	const kvKey = `oauth_state:${await kvKeyHash(state)}`;
	const encrypted = await kv.get(kvKey);

	if (!encrypted) {
		return null;
	}

	try {
		const decrypted = await decryptData(encrypted, encryptionKey);
		const oauthState = JSON.parse(decrypted) as OAuthState;
		// Delete only after successful decryption (single use)
		await kv.delete(kvKey);
		return oauthState;
	} catch (error) {
		safeLogError("Failed to decrypt OAuth state", error);
		return null;
	}
}

/**
 * Mask sensitive data for display purposes
 *
 * @param value - The sensitive value
 * @returns Masked version showing only last 4 characters
 */
export function maskSecret(value: string): string {
	if (value.length <= 4) {
		return "****";
	}
	return `${"*".repeat(Math.min(value.length - 4, 20))}${value.slice(-4)}`;
}
