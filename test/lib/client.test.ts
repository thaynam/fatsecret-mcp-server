/**
 * FatSecret Client Tests
 *
 * Tests for the FatSecret API client.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { FatSecretClient } from "../../src/lib/client.js";
import {
	mockFetchSuccess,
	mockQueryStringResponse,
	mockFetchError,
	mockOAuth2Flow,
	mockOAuth2Error,
} from "../setup.js";

describe("FatSecretClient", () => {
	const clientConfig = {
		clientId: "test_client_id",
		clientSecret: "test_client_secret",
		accessToken: "test_access_token",
		accessTokenSecret: "test_access_token_secret",
	};

	let client: FatSecretClient;

	beforeEach(() => {
		client = new FatSecretClient(clientConfig);
	});

	describe("hasUserAuth", () => {
		it("should return true when access tokens are present", () => {
			expect(client.hasUserAuth()).toBe(true);
		});

		it("should return false when access tokens are missing", () => {
			const noAuthClient = new FatSecretClient({
				clientId: "test_id",
				clientSecret: "test_secret",
			});
			expect(noAuthClient.hasUserAuth()).toBe(false);
		});
	});

	describe("OAuth Flow", () => {
		describe("getRequestToken", () => {
			it("should get a request token from FatSecret", async () => {
				mockQueryStringResponse({
					oauth_token: "request_token_123",
					oauth_token_secret: "request_token_secret_456",
					oauth_callback_confirmed: "true",
				});

				const response = await client.getRequestToken("oob");

				expect(response.oauth_token).toBe("request_token_123");
				expect(response.oauth_token_secret).toBe("request_token_secret_456");
				expect(global.fetch).toHaveBeenCalledTimes(1);
			});
		});

		describe("getAuthorizationUrl", () => {
			it("should generate correct authorization URL", () => {
				const url = client.getAuthorizationUrl("request_token_123");
				expect(url).toBe(
					"https://authentication.fatsecret.com/oauth/authorize?oauth_token=request_token_123",
				);
			});
		});

		describe("getAccessToken", () => {
			it("should exchange request token for access token", async () => {
				mockQueryStringResponse({
					oauth_token: "access_token_abc",
					oauth_token_secret: "access_token_secret_xyz",
					user_id: "user_12345",
				});

				const response = await client.getAccessToken(
					"request_token",
					"request_token_secret",
					"verifier_code",
				);

				expect(response.oauth_token).toBe("access_token_abc");
				expect(response.oauth_token_secret).toBe("access_token_secret_xyz");
				expect(response.user_id).toBe("user_12345");
			});
		});
	});

	describe("Food Database Methods", () => {
		describe("searchFoods", () => {
			it("should search for foods", async () => {
				const mockResponse = {
					foods: {
						food: [
							{ food_id: "123", food_name: "Chicken Breast" },
							{ food_id: "456", food_name: "Grilled Chicken" },
						],
						total_results: "2",
					},
				};
				mockOAuth2Flow(mockResponse);

				const response = await client.searchFoods("chicken", 0, 20);

				expect(response.foods.food).toHaveLength(2);
				expect(response.foods.food[0].food_name).toBe("Chicken Breast");
			});

			it("should include search parameters in request", async () => {
				mockOAuth2Flow({ foods: { food: [], total_results: "0" } });

				await client.searchFoods("apple", 2, 10);

				// Second call is the API request (first is OAuth token)
				const fetchCall = (global.fetch as any).mock.calls[1];
				const url = new URL(fetchCall[0]);
				expect(url.searchParams.get("search_expression")).toBe("apple");
				expect(url.searchParams.get("page_number")).toBe("2");
				expect(url.searchParams.get("max_results")).toBe("10");
			});
		});

		describe("getFood", () => {
			it("should get food details by ID", async () => {
				const mockResponse = {
					food: {
						food_id: "123",
						food_name: "Apple",
						servings: {
							serving: [{ serving_id: "1", calories: "95" }],
						},
					},
				};
				mockOAuth2Flow(mockResponse);

				const response = await client.getFood("123");

				expect(response.food.food_id).toBe("123");
				expect(response.food.food_name).toBe("Apple");
			});
		});
	});

	describe("Recipe Database Methods", () => {
		describe("searchRecipes", () => {
			it("should search for recipes", async () => {
				const mockResponse = {
					recipes: {
						recipe: [{ recipe_id: "789", recipe_name: "Chicken Salad" }],
						total_results: "1",
					},
				};
				mockOAuth2Flow(mockResponse);

				const response = await client.searchRecipes("salad", 0, 20);

				expect(response.recipes.recipe).toHaveLength(1);
				expect(response.recipes.recipe[0].recipe_name).toBe("Chicken Salad");
			});
		});

		describe("getRecipe", () => {
			it("should get recipe details by ID", async () => {
				const mockResponse = {
					recipe: {
						recipe_id: "789",
						recipe_name: "Chicken Salad",
						recipe_description: "A healthy salad",
					},
				};
				mockOAuth2Flow(mockResponse);

				const response = await client.getRecipe("789");

				expect(response.recipe.recipe_id).toBe("789");
			});
		});
	});

	describe("User Data Methods", () => {
		describe("getUserProfile", () => {
			it("should get user profile", async () => {
				const mockResponse = {
					profile: {
						user_id: "12345",
						height_measure: "cm",
						weight_measure: "kg",
					},
				};
				mockFetchSuccess(mockResponse);

				const response = await client.getUserProfile();

				expect(response.profile.user_id).toBe("12345");
			});
		});

		describe("getFoodEntries", () => {
			it("should get food entries for a date", async () => {
				const mockResponse = {
					food_entries: {
						food_entry: [
							{ food_entry_id: "1", food_entry_description: "Breakfast" },
						],
					},
				};
				mockFetchSuccess(mockResponse);

				const response = await client.getFoodEntries("2024-01-15");

				expect(response.food_entries.food_entry).toHaveLength(1);
			});
		});

		describe("addFoodEntry", () => {
			it("should add a food entry", async () => {
				const mockResponse = {
					food_entry_id: { value: "new_entry_123" },
				};
				mockFetchSuccess(mockResponse);

				const response = await client.addFoodEntry(
					"food_123",
					"serving_456",
					1.5,
					"breakfast",
					"2024-01-15",
				);

				expect(response.food_entry_id.value).toBe("new_entry_123");
			});

			it("should convert snack to other meal type", async () => {
				mockFetchSuccess({ food_entry_id: { value: "123" } });

				await client.addFoodEntry("food_123", "serving_456", 1, "snack");

				const fetchCall = (global.fetch as any).mock.calls[0];
				const body = new URLSearchParams(fetchCall[1].body);
				expect(body.get("meal")).toBe("other");
			});
		});

		describe("getWeightMonth", () => {
			it("should get weight entries for a month", async () => {
				const mockResponse = {
					month: {
						day: [
							{ date_int: "19724", weight_kg: "75.5" },
							{ date_int: "19725", weight_kg: "75.3" },
						],
					},
				};
				mockFetchSuccess(mockResponse);

				const response = await client.getWeightMonth("2024-01-15");

				expect(response.month.day).toHaveLength(2);
			});
		});
	});

	describe("Error Handling", () => {
		it("should throw FatSecretApiError on OAuth 2.0 token error", async () => {
			mockOAuth2Error(401, "Unauthorized", {
				error: "invalid_client",
				error_description: "Invalid client credentials",
			});

			await expect(client.searchFoods("test")).rejects.toThrow(
				"OAuth 2.0 token request failed",
			);
		});

		it("should throw FatSecretApiError on API error", async () => {
			// First mock successful OAuth, then API error
			mockFetchSuccess({ access_token: "test_token", expires_in: 86400 });
			mockFetchError(400, "Bad Request", {
				error: { code: 8, message: "Invalid parameter" },
			});

			await expect(client.searchFoods("test")).rejects.toThrow(
				"FatSecret API error",
			);
		});

		it("should require user auth for protected endpoints", async () => {
			const noAuthClient = new FatSecretClient({
				clientId: "test_id",
				clientSecret: "test_secret",
			});

			await expect(noAuthClient.getUserProfile()).rejects.toThrow(
				"User authentication required",
			);
		});
	});
});
