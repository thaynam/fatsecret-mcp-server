/**
 * FatSecret API Client
 *
 * Provides methods for interacting with the FatSecret API with built-in OAuth 1.0a signing.
 */

import { createHmac } from "node:crypto";
import OAuth from "oauth-1.0a";
import { parseResponse, dateToFatSecretFormat, normalizeMealType, truncate } from "./transforms.js";
import { FatSecretApiError } from "./errors.js";
import type { MealType } from "./schemas.js";
import { OAUTH2_TOKEN_BUFFER_MS, MAX_ERROR_TEXT_LENGTH } from "./constants.js";

// FatSecret API URLs
const API_BASE_URL = "https://platform.fatsecret.com/rest/server.api";
const OAUTH2_TOKEN_URL = "https://oauth.fatsecret.com/connect/token";
// Official OAuth 1.0a endpoints from FatSecret docs
const REQUEST_TOKEN_URL = "https://authentication.fatsecret.com/oauth/request_token";
const AUTHORIZE_URL = "https://authentication.fatsecret.com/oauth/authorize";
const ACCESS_TOKEN_URL = "https://authentication.fatsecret.com/oauth/access_token";

export interface FatSecretClientConfig {
	clientId: string;
	clientSecret: string;
	consumerSecret?: string; // OAuth 1.0a secret (falls back to clientSecret)
	// OAuth 1.0a tokens (for user data)
	accessToken?: string;
	accessTokenSecret?: string;
	// OAuth 2.0 token (for public data)
	oauth2AccessToken?: string;
	oauth2ExpiresAt?: number;
}

export interface OAuthTokenResponse {
	oauth_token: string;
	oauth_token_secret: string;
	oauth_callback_confirmed?: string;
	user_id?: string;
}

export class FatSecretClient {
	private clientId: string;
	private clientSecret: string;
	// OAuth 1.0a tokens (for user data)
	private accessToken?: string;
	private accessTokenSecret?: string;
	// OAuth 2.0 token (for public data)
	private oauth2AccessToken?: string;
	private oauth2ExpiresAt?: number;

	private oauth: OAuth;

	constructor(config: FatSecretClientConfig) {
		this.clientId = config.clientId;
		this.clientSecret = config.clientSecret;
		this.accessToken = config.accessToken;
		this.accessTokenSecret = config.accessTokenSecret;
		this.oauth2AccessToken = config.oauth2AccessToken;
		this.oauth2ExpiresAt = config.oauth2ExpiresAt;
		// OAuth 1.0a uses Consumer Secret (falls back to Client Secret for backwards compat)
		const oauthSecret = config.consumerSecret || config.clientSecret;
		this.oauth = new OAuth({
			consumer: { key: this.clientId, secret: oauthSecret },
			signature_method: "HMAC-SHA1",
			hash_function(baseString: string, key: string) {
				return createHmac("sha1", key).update(baseString).digest("base64");
			},
		});
	}

	/**
	 * Check if the client has user authentication (OAuth 1.0a access tokens)
	 */
	hasUserAuth(): boolean {
		return !!(this.accessToken && this.accessTokenSecret);
	}

	/**
	 * Check if OAuth 2.0 token is valid
	 */
	private isOAuth2TokenValid(): boolean {
		if (!this.oauth2AccessToken || !this.oauth2ExpiresAt) {
			return false;
		}
		// Consider token expired 5 minutes before actual expiration
		return Date.now() < this.oauth2ExpiresAt - OAUTH2_TOKEN_BUFFER_MS;
	}

	/**
	 * Get OAuth 2.0 access token using Client Credentials flow
	 * This is used for public data (food search, recipes)
	 */
	async getOAuth2Token(): Promise<{ accessToken: string; expiresAt: number }> {
		// Return cached token if still valid
		if (this.isOAuth2TokenValid() && this.oauth2AccessToken && this.oauth2ExpiresAt) {
			return {
				accessToken: this.oauth2AccessToken,
				expiresAt: this.oauth2ExpiresAt,
			};
		}

		// Request new token
		const credentials = btoa(`${this.clientId}:${this.clientSecret}`);

		const response = await fetch(OAUTH2_TOKEN_URL, {
			method: "POST",
			headers: {
				Authorization: `Basic ${credentials}`,
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: "grant_type=client_credentials&scope=basic",
		});

		if (!response.ok) {
			const text = await response.text();
			const safeText = truncate(text, MAX_ERROR_TEXT_LENGTH);
			throw new FatSecretApiError(
				`OAuth 2.0 token request failed: ${response.status} - ${safeText}`,
				response.status,
			);
		}

		const data = (await response.json()) as {
			access_token: string;
			expires_in: number;
		};
		const expiresAt = Date.now() + data.expires_in * 1000;

		// Cache the token
		this.oauth2AccessToken = data.access_token;
		this.oauth2ExpiresAt = expiresAt;

		return {
			accessToken: data.access_token,
			expiresAt,
		};
	}

	/**
	 * Validate credentials by attempting to get an OAuth 2.0 token
	 */
	async validateCredentials(): Promise<boolean> {
		try {
			await this.getOAuth2Token();
			return true;
		} catch {
			return false;
		}
	}

	/**
	 * Core OAuth 1.0a signed request.
	 * Signs the request using the oauth-1.0a library, then dispatches it.
	 */
	private async signedFetch(
		method: "GET" | "POST",
		url: string,
		params: Record<string, string> = {},
		additionalOAuthParams: Record<string, string> = {},
		token?: string,
		tokenSecret?: string,
	): Promise<unknown> {
		const requestData = {
			url,
			method,
			data: { ...params, ...additionalOAuthParams },
		};

		const oauthToken = token ? { key: token, secret: tokenSecret || "" } : undefined;
		const oauthData = this.oauth.authorize(requestData, oauthToken);

		// Build signed params: oauth data (stringified) + API params + additional OAuth params
		const signedParams: Record<string, string> = {};
		for (const [key, value] of Object.entries(oauthData)) {
			signedParams[key] = String(value);
		}
		Object.assign(signedParams, params);
		Object.assign(signedParams, additionalOAuthParams);

		let requestUrl = url;
		const options: RequestInit = {
			method,
			headers: {},
		};

		if (method === "GET") {
			const queryString = new URLSearchParams(signedParams).toString();
			requestUrl = `${url}?${queryString}`;
		} else if (method === "POST") {
			(options.headers as Record<string, string>)["Content-Type"] =
				"application/x-www-form-urlencoded";
			options.body = new URLSearchParams(signedParams).toString();
		}

		const response = await fetch(requestUrl, options);
		const text = await response.text();

		if (!response.ok) {
			const safeText = truncate(text, MAX_ERROR_TEXT_LENGTH);
			throw new FatSecretApiError(
				`FatSecret API error: ${response.status} - ${safeText}`,
				response.status,
				parseResponse(text),
			);
		}

		return parseResponse(text);
	}

	/**
	 * Make an API request using OAuth 2.0 (for public data)
	 */
	private async apiRequestOAuth2(
		apiMethod: string,
		params: Record<string, string> = {},
	): Promise<unknown> {
		const { accessToken } = await this.getOAuth2Token();

		const allParams = {
			method: apiMethod,
			format: "json",
			...params,
		};

		const queryString = new URLSearchParams(allParams).toString();
		const requestUrl = `${API_BASE_URL}?${queryString}`;

		const response = await fetch(requestUrl, {
			method: "GET",
			headers: {
				Authorization: `Bearer ${accessToken}`,
			},
		});

		const text = await response.text();

		if (!response.ok) {
			const safeText = truncate(text, MAX_ERROR_TEXT_LENGTH);
			throw new FatSecretApiError(
				`FatSecret API error: ${response.status} - ${safeText}`,
				response.status,
				parseResponse(text),
			);
		}

		return parseResponse(text);
	}

	/**
	 * Make an API request using OAuth 1.0a (for user data)
	 */
	private async apiRequestOAuth1(
		method: "GET" | "POST",
		apiMethod: string,
		params: Record<string, string> = {},
	): Promise<unknown> {
		if (!this.hasUserAuth()) {
			throw new FatSecretApiError(
				"User authentication required. Please connect your FatSecret account.",
				401,
			);
		}

		const allParams = {
			method: apiMethod,
			format: "json",
			...params,
		};

		return this.signedFetch(
			method,
			API_BASE_URL,
			allParams,
			{},
			this.accessToken,
			this.accessTokenSecret,
		);
	}

	/**
	 * Make an API request (to the main FatSecret API endpoint)
	 * Uses OAuth 2.0 for public data, OAuth 1.0a for user data
	 */
	private async apiRequest(
		method: "GET" | "POST",
		apiMethod: string,
		params: Record<string, string> = {},
		requiresAuth = false,
	): Promise<unknown> {
		if (requiresAuth) {
			return this.apiRequestOAuth1(method, apiMethod, params);
		}
		return this.apiRequestOAuth2(apiMethod, params);
	}

	// =========================================================================
	// OAuth Flow Methods
	// =========================================================================

	/**
	 * Get a request token to start the OAuth flow
	 * Uses POST with Authorization header as per OAuth 1.0a spec
	 */
	async getRequestToken(callbackUrl = "oob"): Promise<OAuthTokenResponse> {
		const response = (await this.signedFetch(
			"POST",
			REQUEST_TOKEN_URL,
			{},
			{
				oauth_callback: callbackUrl,
			},
		)) as Record<string, string>;

		return {
			oauth_token: response.oauth_token,
			oauth_token_secret: response.oauth_token_secret,
			oauth_callback_confirmed: response.oauth_callback_confirmed,
		};
	}

	/**
	 * Get the authorization URL for the user to visit
	 */
	getAuthorizationUrl(requestToken: string): string {
		return `${AUTHORIZE_URL}?oauth_token=${encodeURIComponent(requestToken)}`;
	}

	/**
	 * Exchange a request token and verifier for an access token
	 * Uses GET with Authorization header as per OAuth 1.0a spec
	 */
	async getAccessToken(
		requestToken: string,
		requestTokenSecret: string,
		verifier: string,
	): Promise<OAuthTokenResponse> {
		const response = (await this.signedFetch(
			"GET",
			ACCESS_TOKEN_URL,
			{},
			{ oauth_verifier: verifier },
			requestToken,
			requestTokenSecret,
		)) as Record<string, string>;

		return {
			oauth_token: response.oauth_token,
			oauth_token_secret: response.oauth_token_secret,
			user_id: response.user_id,
		};
	}

	// =========================================================================
	// Profile Methods (Two-legged OAuth - consumer key only)
	// =========================================================================

	/**
	 * Create a new user profile via the Profile API.
	 * Uses two-legged OAuth (consumer key/secret only, no access token needed).
	 * Returns auth tokens that persist indefinitely.
	 */
	async profileCreate(userId: string): Promise<{ authToken: string; authSecret: string }> {
		const response = (await this.signedFetch("POST", API_BASE_URL, {
			method: "profile.create",
			user_id: userId,
			format: "json",
		})) as { profile: { auth_token: string; auth_secret: string } };

		return {
			authToken: response.profile.auth_token,
			authSecret: response.profile.auth_secret,
		};
	}

	/**
	 * Get auth tokens for an existing profile.
	 * Uses two-legged OAuth (consumer key/secret only).
	 */
	async profileGetAuth(userId: string): Promise<{ authToken: string; authSecret: string }> {
		const response = (await this.signedFetch("GET", API_BASE_URL, {
			method: "profile.get_auth",
			user_id: userId,
			format: "json",
		})) as { profile: { auth_token: string; auth_secret: string } };

		return {
			authToken: response.profile.auth_token,
			authSecret: response.profile.auth_secret,
		};
	}

	// =========================================================================
	// Food Database Methods (No user auth required)
	// =========================================================================

	/**
	 * Search for foods in the FatSecret database
	 */
	async searchFoods(searchExpression: string, pageNumber = 0, maxResults = 20): Promise<unknown> {
		return this.apiRequest("GET", "foods.search", {
			search_expression: searchExpression,
			page_number: pageNumber.toString(),
			max_results: maxResults.toString(),
		});
	}

	/**
	 * Get detailed information about a specific food
	 */
	async getFood(foodId: string): Promise<unknown> {
		return this.apiRequest("GET", "food.get", {
			food_id: foodId,
		});
	}

	// =========================================================================
	// Recipe Database Methods (No user auth required)
	// =========================================================================

	/**
	 * Search for recipes in the FatSecret database
	 */
	async searchRecipes(
		searchExpression: string,
		pageNumber = 0,
		maxResults = 20,
	): Promise<unknown> {
		return this.apiRequest("GET", "recipes.search", {
			search_expression: searchExpression,
			page_number: pageNumber.toString(),
			max_results: maxResults.toString(),
		});
	}

	/**
	 * Get detailed information about a specific recipe
	 */
	async getRecipe(recipeId: string): Promise<unknown> {
		return this.apiRequest("GET", "recipe.get", {
			recipe_id: recipeId,
		});
	}

	// =========================================================================
	// User Data Methods (Requires user auth)
	// =========================================================================

	/**
	 * Get the authenticated user's profile
	 */
	async getUserProfile(): Promise<unknown> {
		return this.apiRequest("GET", "profile.get", {}, true);
	}

	/**
	 * Get food diary entries for a specific date
	 */
	async getFoodEntries(date?: string): Promise<unknown> {
		return this.apiRequest(
			"GET",
			"food_entries.get",
			{
				date: dateToFatSecretFormat(date),
			},
			true,
		);
	}

	/**
	 * Add a food entry to the user's diary
	 */
	async addFoodEntry(
		foodId: string,
		servingId: string,
		quantity: number,
		mealType: MealType,
		date?: string,
	): Promise<unknown> {
		return this.apiRequest(
			"POST",
			"food_entry.create",
			{
				food_id: foodId,
				serving_id: servingId,
				quantity: quantity.toString(),
				meal: normalizeMealType(mealType),
				date: dateToFatSecretFormat(date),
			},
			true,
		);
	}

	/**
	 * Get weight entries for a specific month
	 */
	async getWeightMonth(date?: string): Promise<unknown> {
		return this.apiRequest(
			"GET",
			"weights.get_month",
			{
				date: dateToFatSecretFormat(date),
			},
			true,
		);
	}
}
