/**
 * OAuth 1.0a signing implementation for FatSecret API
 * Based on oauth-1.0a library (https://github.com/ddo/oauth-1.0a)
 * Uses node:crypto HMAC-SHA1 (available via nodejs_compat)
 */

import { createHmac } from "node:crypto";

/**
 * Percent-encode a string according to RFC 5849 Section 3.6
 * Matches oauth-1.0a library implementation exactly
 */
export function percentEncode(str: string): string {
	return encodeURIComponent(str)
		.replace(/!/g, "%21")
		.replace(/\*/g, "%2A")
		.replace(/'/g, "%27")
		.replace(/\(/g, "%28")
		.replace(/\)/g, "%29");
}

/**
 * Generate a cryptographically secure random nonce (hex, 48 chars)
 */
export function generateNonce(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(24));
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/**
 * Generate a Unix timestamp
 */
export function generateTimestamp(): string {
	return Math.floor(Date.now() / 1000).toString();
}

/**
 * Percent encode all keys and values in an object
 */
function percentEncodeData(
	data: Record<string, string>,
): Record<string, string> {
	const result: Record<string, string> = {};
	for (const key in data) {
		result[percentEncode(key)] = percentEncode(data[key]);
	}
	return result;
}

/**
 * Sort object by key and return as array of {key, value}
 */
function sortObject(
	data: Record<string, string>,
): Array<{ key: string; value: string }> {
	const keys = Object.keys(data).sort();
	return keys.map((key) => ({ key, value: data[key] }));
}

/**
 * Create the parameter string from oauth data
 * Matches oauth-1.0a library getParameterString
 */
function getParameterString(
	oauthData: Record<string, string>,
	requestData: Record<string, string> = {},
): string {
	// Merge oauth data with request data
	const merged = { ...oauthData, ...requestData };

	// Percent encode all keys and values
	const encoded = percentEncodeData(merged);

	// Sort by key
	const sorted = sortObject(encoded);

	// Build parameter string
	return sorted.map((item) => `${item.key}=${item.value}`).join("&");
}

/**
 * Create the signing key
 * Matches oauth-1.0a library getSigningKey
 */
export function createSigningKey(
	consumerSecret: string,
	tokenSecret = "",
): string {
	return `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;
}

/**
 * Create the signature base string
 * Matches oauth-1.0a library getBaseString
 */
export function createSignatureBaseString(
	method: string,
	url: string,
	oauthData: Record<string, string>,
	requestData: Record<string, string> = {},
): string {
	// Get base URL (without query string)
	const baseUrl = url.split("?")[0];

	// Get parameter string
	const parameterString = getParameterString(oauthData, requestData);

	// Build base string: METHOD&URL&PARAMS
	return `${method.toUpperCase()}&${percentEncode(baseUrl)}&${percentEncode(parameterString)}`;
}

/**
 * Generate HMAC-SHA1 signature using node:crypto
 */
export function generateSignature(
	method: string,
	url: string,
	oauthData: Record<string, string>,
	consumerSecret: string,
	tokenSecret = "",
	requestData: Record<string, string> = {},
): string {
	const baseString = createSignatureBaseString(
		method,
		url,
		oauthData,
		requestData,
	);
	const signingKey = createSigningKey(consumerSecret, tokenSecret);

	return createHmac("sha1", signingKey).update(baseString).digest("base64");
}

/**
 * Build OAuth parameters object with standard fields
 */
export function buildOAuthParams(
	consumerKey: string,
	additionalParams: Record<string, string> = {},
	token?: string,
): Record<string, string> {
	const params: Record<string, string> = {
		oauth_consumer_key: consumerKey,
		oauth_nonce: generateNonce(),
		oauth_signature_method: "HMAC-SHA1",
		oauth_timestamp: generateTimestamp(),
		oauth_version: "1.0",
		...additionalParams,
	};

	if (token) {
		params.oauth_token = token;
	}

	return params;
}

/**
 * Sign an OAuth request and return all parameters including signature
 */
export function signRequest(
	method: string,
	url: string,
	consumerKey: string,
	consumerSecret: string,
	additionalOAuthParams: Record<string, string> = {},
	requestData: Record<string, string> = {},
	token?: string,
	tokenSecret?: string,
): Record<string, string> {
	// Build OAuth parameters (without signature)
	const oauthParams = buildOAuthParams(
		consumerKey,
		additionalOAuthParams,
		token,
	);

	// Generate signature
	const signature = generateSignature(
		method,
		url,
		oauthParams,
		consumerSecret,
		tokenSecret || "",
		requestData,
	);

	// Return all params with signature
	return {
		...oauthParams,
		...requestData,
		oauth_signature: signature,
	};
}

/**
 * Build an OAuth Authorization header
 */
export function buildAuthorizationHeader(
	oauthParams: Record<string, string>,
): string {
	const sorted = Object.keys(oauthParams)
		.filter((key) => key.startsWith("oauth_"))
		.sort();

	const headerParts = sorted
		.map((key) => `${percentEncode(key)}="${percentEncode(oauthParams[key])}"`)
		.join(", ");

	return `OAuth ${headerParts}`;
}
