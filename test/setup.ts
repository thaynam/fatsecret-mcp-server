/**
 * Test Setup
 *
 * Global test configuration and mock helpers.
 */

import { beforeEach, vi } from "vitest";

// Mock global fetch
global.fetch = vi.fn();

// Reset mocks before each test
beforeEach(() => {
	vi.clearAllMocks();
});

/**
 * Mock a successful fetch response
 */
export function mockFetchSuccess(data: any, status = 200) {
	(global.fetch as any).mockResolvedValueOnce({
		ok: status >= 200 && status < 300,
		status,
		statusText: "OK",
		headers: new Headers({ "Content-Type": "application/json" }),
		text: async () => JSON.stringify(data),
		json: async () => data,
	});
}

/**
 * Mock a fetch error response
 */
export function mockFetchError(status: number, message: string, data?: any) {
	(global.fetch as any).mockResolvedValueOnce({
		ok: false,
		status,
		statusText: message,
		headers: new Headers({ "Content-Type": "application/json" }),
		text: async () => JSON.stringify(data || { error: message }),
		json: async () => data || { error: message },
	});
}

/**
 * Mock a query string response (OAuth endpoints)
 */
export function mockQueryStringResponse(
	data: Record<string, string>,
	status = 200,
) {
	const queryString = new URLSearchParams(data).toString();
	(global.fetch as any).mockResolvedValueOnce({
		ok: status >= 200 && status < 300,
		status,
		statusText: "OK",
		headers: new Headers({
			"Content-Type": "application/x-www-form-urlencoded",
		}),
		text: async () => queryString,
		json: async () => {
			throw new Error("Not JSON");
		},
	});
}

/**
 * Mock OAuth 2.0 token response followed by API response
 * Used for public data methods that use OAuth 2.0 Client Credentials flow
 */
export function mockOAuth2Flow(apiData: any, apiStatus = 200) {
	// First call: OAuth 2.0 token request
	(global.fetch as any).mockResolvedValueOnce({
		ok: true,
		status: 200,
		statusText: "OK",
		headers: new Headers({ "Content-Type": "application/json" }),
		text: async () =>
			JSON.stringify({ access_token: "test_oauth2_token", expires_in: 86400 }),
		json: async () => ({
			access_token: "test_oauth2_token",
			expires_in: 86400,
		}),
	});

	// Second call: API request
	(global.fetch as any).mockResolvedValueOnce({
		ok: apiStatus >= 200 && apiStatus < 300,
		status: apiStatus,
		statusText: apiStatus >= 200 && apiStatus < 300 ? "OK" : "Error",
		headers: new Headers({ "Content-Type": "application/json" }),
		text: async () => JSON.stringify(apiData),
		json: async () => apiData,
	});
}

/**
 * Mock OAuth 2.0 token error
 */
export function mockOAuth2Error(status: number, message: string, data?: any) {
	(global.fetch as any).mockResolvedValueOnce({
		ok: false,
		status,
		statusText: message,
		headers: new Headers({ "Content-Type": "application/json" }),
		text: async () => JSON.stringify(data || { error: message }),
		json: async () => data || { error: message },
	});
}

/**
 * Create a mock KVNamespace
 */
export function createMockKV(): KVNamespace {
	const store = new Map<string, string>();

	return {
		get: vi.fn(async (key: string) => store.get(key) || null),
		put: vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		}),
		delete: vi.fn(async (key: string) => {
			store.delete(key);
		}),
		list: vi.fn(),
		getWithMetadata: vi.fn(),
	} as unknown as KVNamespace;
}
