/**
 * OAuth Signing Tests
 *
 * Tests for OAuth 1.0a signature generation.
 */

import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import OAuth from "oauth-1.0a";
import {
	percentEncode,
	generateNonce,
	generateTimestamp,
	createSignatureBaseString,
	createSigningKey,
	generateSignature,
	buildOAuthParams,
} from "../../src/lib/oauth.js";

describe("OAuth 1.0a Signing", () => {
	describe("percentEncode", () => {
		it("should encode basic special characters", () => {
			expect(percentEncode("hello world")).toBe("hello%20world");
			expect(percentEncode("test=value")).toBe("test%3Dvalue");
			expect(percentEncode("a&b")).toBe("a%26b");
		});

		it("should encode characters that encodeURIComponent misses", () => {
			expect(percentEncode("test!")).toBe("test%21");
			expect(percentEncode("test'")).toBe("test%27");
			expect(percentEncode("test(")).toBe("test%28");
			expect(percentEncode("test)")).toBe("test%29");
			expect(percentEncode("test*")).toBe("test%2A");
		});

		it("should leave alphanumeric and safe characters unchanged", () => {
			expect(percentEncode("abc123")).toBe("abc123");
			expect(percentEncode("test-value")).toBe("test-value");
			expect(percentEncode("test_value")).toBe("test_value");
			expect(percentEncode("test.value")).toBe("test.value");
			expect(percentEncode("test~value")).toBe("test~value");
		});
	});

	describe("generateNonce", () => {
		it("should generate a 48-character hex string", () => {
			const nonce = generateNonce();
			expect(nonce).toHaveLength(48);
			expect(nonce).toMatch(/^[a-f0-9]+$/);
		});

		it("should generate unique nonces", () => {
			const nonce1 = generateNonce();
			const nonce2 = generateNonce();
			expect(nonce1).not.toBe(nonce2);
		});
	});

	describe("generateTimestamp", () => {
		it("should return a Unix timestamp string", () => {
			const timestamp = generateTimestamp();
			const parsed = parseInt(timestamp, 10);
			expect(parsed).toBeGreaterThan(1700000000); // After Nov 2023
			expect(parsed).toBeLessThan(2000000000); // Before 2033
		});
	});

	describe("createSignatureBaseString", () => {
		it("should sort parameters alphabetically", () => {
			const oauthData = {
				z_param: "z",
				a_param: "a",
				m_param: "m",
			};

			const baseString = createSignatureBaseString(
				"GET",
				"https://example.com/api",
				oauthData,
				{},
			);

			// Parameters should be sorted: a_param, m_param, z_param
			expect(baseString).toContain("a_param%3Da%26m_param%3Dm%26z_param%3Dz");
		});

		it("should include method in uppercase", () => {
			const oauthData = { test: "value" };
			const baseString = createSignatureBaseString(
				"get",
				"https://example.com/api",
				oauthData,
				{},
			);
			expect(baseString).toMatch(/^GET&/);
		});

		it("should percent-encode the URL", () => {
			const oauthData = { test: "value" };
			const baseString = createSignatureBaseString(
				"GET",
				"https://example.com/api",
				oauthData,
				{},
			);
			expect(baseString).toContain("https%3A%2F%2Fexample.com%2Fapi");
		});
	});

	describe("createSigningKey", () => {
		it("should combine consumer secret and token secret with &", () => {
			const key = createSigningKey("consumerSecret", "tokenSecret");
			expect(key).toBe("consumerSecret&tokenSecret");
		});

		it("should handle empty token secret", () => {
			const key = createSigningKey("consumerSecret");
			expect(key).toBe("consumerSecret&");
		});

		it("should percent-encode secrets with special characters", () => {
			const key = createSigningKey("secret&key", "token=secret");
			expect(key).toBe("secret%26key&token%3Dsecret");
		});
	});

	describe("generateSignature", () => {
		it("should generate a base64-encoded signature", async () => {
			const signature = await generateSignature(
				"GET",
				"https://api.example.com/resource",
				{ oauth_consumer_key: "test_key", oauth_timestamp: "1234567890" },
				"consumer_secret",
				"token_secret",
				{},
			);

			// Should be base64 encoded
			expect(signature).toMatch(/^[A-Za-z0-9+/]+=*$/);
		});

		it("should produce consistent signatures for same inputs", async () => {
			const oauthData = {
				oauth_consumer_key: "test_key",
				oauth_timestamp: "1234567890",
				oauth_nonce: "fixed_nonce",
			};

			const sig1 = await generateSignature(
				"GET",
				"https://api.example.com",
				oauthData,
				"secret",
				"token",
				{},
			);

			const sig2 = await generateSignature(
				"GET",
				"https://api.example.com",
				oauthData,
				"secret",
				"token",
				{},
			);

			expect(sig1).toBe(sig2);
		});

		it("should match oauth-1.0a library signature for request_token", async () => {
			// Create oauth-1.0a instance with same consumer credentials
			const consumerKey = "test_consumer_key";
			const consumerSecret = "test_consumer_secret";

			const oauth = new OAuth({
				consumer: { key: consumerKey, secret: consumerSecret },
				signature_method: "HMAC-SHA1",
				hash_function(baseString: string, key: string) {
					return createHmac("sha1", key).update(baseString).digest("base64");
				},
			});

			// Fixed timestamp and nonce for reproducibility
			const fixedNonce = "abcdef123456789012345678901234ab";
			const fixedTimestamp = "1234567890";

			// Request data matching request_token endpoint
			const requestData = {
				url: "https://authentication.fatsecret.com/oauth/request_token",
				method: "POST",
				data: { oauth_callback: "oob" },
			};

			// Get signature from oauth-1.0a library
			// We need to override nonce and timestamp
			const originalGetNonce = oauth.getNonce.bind(oauth);
			const originalGetTimestamp = oauth.getTimeStamp.bind(oauth);
			oauth.getNonce = () => fixedNonce;
			oauth.getTimeStamp = () => Number.parseInt(fixedTimestamp, 10);

			const oauthLibResult = oauth.authorize(requestData);
			const expectedSignature = oauthLibResult.oauth_signature;

			// Restore original functions
			oauth.getNonce = originalGetNonce;
			oauth.getTimeStamp = originalGetTimestamp;

			// Now generate with our implementation using same params
			const ourOauthData = {
				oauth_consumer_key: consumerKey,
				oauth_nonce: fixedNonce,
				oauth_signature_method: "HMAC-SHA1",
				oauth_timestamp: fixedTimestamp,
				oauth_version: "1.0",
				oauth_callback: "oob",
			};

			const ourSignature = await generateSignature(
				"POST",
				"https://authentication.fatsecret.com/oauth/request_token",
				ourOauthData,
				consumerSecret,
				"",
				{},
			);

			expect(ourSignature).toBe(expectedSignature);
		});

		it("should match oauth-1.0a library signature with token", async () => {
			const consumerKey = "my_key";
			const consumerSecret = "my_secret";
			const tokenKey = "token_key";
			const tokenSecret = "token_secret";

			const oauth = new OAuth({
				consumer: { key: consumerKey, secret: consumerSecret },
				signature_method: "HMAC-SHA1",
				hash_function(baseString: string, key: string) {
					return createHmac("sha1", key).update(baseString).digest("base64");
				},
			});

			const fixedNonce = "xyz12345678901234567890123456789";
			const fixedTimestamp = "1700000000";

			const requestData = {
				url: "https://platform.fatsecret.com/rest/server.api",
				method: "GET",
				data: { method: "profile.get", format: "json" },
			};

			oauth.getNonce = () => fixedNonce;
			oauth.getTimeStamp = () => Number.parseInt(fixedTimestamp, 10);

			const oauthLibResult = oauth.authorize(requestData, {
				key: tokenKey,
				secret: tokenSecret,
			});
			const expectedSignature = oauthLibResult.oauth_signature;

			// Our implementation
			const ourOauthData = {
				oauth_consumer_key: consumerKey,
				oauth_nonce: fixedNonce,
				oauth_signature_method: "HMAC-SHA1",
				oauth_timestamp: fixedTimestamp,
				oauth_version: "1.0",
				oauth_token: tokenKey,
			};

			const ourSignature = await generateSignature(
				"GET",
				"https://platform.fatsecret.com/rest/server.api",
				ourOauthData,
				consumerSecret,
				tokenSecret,
				{ method: "profile.get", format: "json" },
			);

			expect(ourSignature).toBe(expectedSignature);
		});
	});

	describe("buildOAuthParams", () => {
		it("should include standard OAuth parameters", () => {
			const params = buildOAuthParams("consumer_key_123");

			expect(params.oauth_consumer_key).toBe("consumer_key_123");
			expect(params.oauth_signature_method).toBe("HMAC-SHA1");
			expect(params.oauth_version).toBe("1.0");
			expect(params.oauth_nonce).toBeDefined();
			expect(params.oauth_timestamp).toBeDefined();
		});

		it("should include token if provided", () => {
			const params = buildOAuthParams("consumer_key", {}, "access_token_123");

			expect(params.oauth_token).toBe("access_token_123");
		});

		it("should not include token if not provided", () => {
			const params = buildOAuthParams("consumer_key");

			expect(params.oauth_token).toBeUndefined();
		});

		it("should include additional params", () => {
			const params = buildOAuthParams("consumer_key", {
				oauth_callback: "oob",
			});

			expect(params.oauth_callback).toBe("oob");
		});
	});
});
