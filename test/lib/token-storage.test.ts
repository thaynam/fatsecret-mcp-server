import { describe, it, expect } from "vitest";
import {
	encryptData,
	decryptData,
	kvKeyHash,
	generateSessionToken,
	maskSecret,
} from "../../src/lib/token-storage.js";

describe("Encryption", () => {
	// 64-char hex key (32 bytes)
	const testKey = "a".repeat(64);

	it("should encrypt and decrypt data round-trip", async () => {
		const plaintext = '{"clientId":"test","clientSecret":"secret"}';
		const encrypted = await encryptData(plaintext, testKey);
		const decrypted = await decryptData(encrypted, testKey);
		expect(decrypted).toBe(plaintext);
	});

	it("should produce different ciphertexts for same plaintext (random IV)", async () => {
		const plaintext = "same data";
		const a = await encryptData(plaintext, testKey);
		const b = await encryptData(plaintext, testKey);
		expect(a).not.toBe(b);
	});

	it("should reject invalid encryption key format", async () => {
		await expect(encryptData("test", "not-hex")).rejects.toThrow(
			"Encryption key must be exactly 64 hex characters",
		);
	});

	it("should reject short encryption key", async () => {
		await expect(encryptData("test", "abcd")).rejects.toThrow(
			"Encryption key must be exactly 64 hex characters",
		);
	});
});

describe("kvKeyHash", () => {
	it("should produce consistent hex hash", async () => {
		const hash1 = await kvKeyHash("test-value");
		const hash2 = await kvKeyHash("test-value");
		expect(hash1).toBe(hash2);
		expect(hash1).toMatch(/^[0-9a-f]{64}$/);
	});

	it("should produce different hashes for different inputs", async () => {
		const hash1 = await kvKeyHash("value-a");
		const hash2 = await kvKeyHash("value-b");
		expect(hash1).not.toBe(hash2);
	});
});

describe("generateSessionToken", () => {
	it("should produce 64-char hex string", () => {
		const token = generateSessionToken();
		expect(token).toMatch(/^[0-9a-f]{64}$/);
	});

	it("should produce unique tokens", () => {
		const a = generateSessionToken();
		const b = generateSessionToken();
		expect(a).not.toBe(b);
	});
});

describe("maskSecret", () => {
	it("should mask long secrets showing last 4 chars", () => {
		expect(maskSecret("abcdefghij")).toBe("******ghij");
	});

	it("should return **** for short secrets", () => {
		expect(maskSecret("ab")).toBe("****");
		expect(maskSecret("abcd")).toBe("****");
	});

	it("should cap mask at 20 asterisks", () => {
		const long = "a".repeat(100);
		const masked = maskSecret(long);
		const stars = masked.replace(/[^*]/g, "");
		expect(stars.length).toBe(20);
		expect(masked.endsWith(long.slice(-4))).toBe(true);
	});
});
