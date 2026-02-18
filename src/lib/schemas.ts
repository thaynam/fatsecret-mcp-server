/**
 * Zod schemas for FatSecret MCP tools
 */
import { z } from "zod";

// ============================================================================
// Enums
// ============================================================================

export const MealTypeEnum = z.enum(["breakfast", "lunch", "dinner", "snack"]);
export type MealType = z.infer<typeof MealTypeEnum>;

// ============================================================================
// Tool Parameter Schemas
// ============================================================================

export const SetCredentialsSchema = z.object({
	clientId: z.string().describe("Your FatSecret Client ID"),
	clientSecret: z.string().describe("Your FatSecret Client Secret"),
});

export const StartOAuthFlowSchema = z.object({
	callbackUrl: z
		.string()
		.optional()
		.describe('OAuth callback URL (use "oob" for out-of-band, default: "oob")'),
});

export const CompleteOAuthFlowSchema = z.object({
	requestToken: z.string().describe("The request token from start_oauth_flow"),
	requestTokenSecret: z
		.string()
		.describe("The request token secret from start_oauth_flow"),
	verifier: z
		.string()
		.describe("The OAuth verifier from the authorization page"),
});

export const SearchFoodsSchema = z.object({
	searchExpression: z
		.string()
		.describe('Search term for foods (e.g., "chicken breast", "apple")'),
	pageNumber: z
		.number()
		.optional()
		.describe("Page number for results (default: 0)"),
	maxResults: z
		.number()
		.optional()
		.describe("Maximum results per page (default: 20, max: 50)"),
});

export const GetFoodSchema = z.object({
	foodId: z.string().describe("The FatSecret food ID"),
});

export const SearchRecipesSchema = z.object({
	searchExpression: z.string().describe("Search term for recipes"),
	pageNumber: z
		.number()
		.optional()
		.describe("Page number for results (default: 0)"),
	maxResults: z
		.number()
		.optional()
		.describe("Maximum results per page (default: 20, max: 50)"),
});

export const GetRecipeSchema = z.object({
	recipeId: z.string().describe("The FatSecret recipe ID"),
});

export const GetUserFoodEntriesSchema = z.object({
	date: z
		.string()
		.optional()
		.describe("Date in YYYY-MM-DD format (default: today)"),
});

export const AddFoodEntrySchema = z.object({
	foodId: z.string().describe("The FatSecret food ID"),
	servingId: z.string().describe("The serving ID for the food"),
	quantity: z.number().describe("Quantity of the serving"),
	mealType: MealTypeEnum.describe(
		"Meal type (breakfast, lunch, dinner, snack)",
	),
	date: z
		.string()
		.optional()
		.describe("Date in YYYY-MM-DD format (default: today)"),
});

export const GetWeightMonthSchema = z.object({
	date: z
		.string()
		.optional()
		.describe(
			"Date in YYYY-MM-DD format to specify the month (default: current month)",
		),
});

// ============================================================================
// Response Types (for reference)
// ============================================================================

export interface FoodSearchResult {
	foods?: {
		food?: FoodSummary | FoodSummary[];
		max_results?: string;
		page_number?: string;
		total_results?: string;
	};
}

export interface FoodSummary {
	food_id: string;
	food_name: string;
	food_type: string;
	food_url: string;
	food_description?: string;
	brand_name?: string;
}

export interface FoodDetail {
	food?: {
		food_id: string;
		food_name: string;
		food_type: string;
		food_url: string;
		brand_name?: string;
		servings?: {
			serving?: Serving | Serving[];
		};
	};
}

export interface Serving {
	serving_id: string;
	serving_description: string;
	serving_url: string;
	metric_serving_amount?: string;
	metric_serving_unit?: string;
	calories?: string;
	carbohydrate?: string;
	protein?: string;
	fat?: string;
	saturated_fat?: string;
	fiber?: string;
	sugar?: string;
	sodium?: string;
}

export interface RecipeSearchResult {
	recipes?: {
		recipe?: RecipeSummary | RecipeSummary[];
		max_results?: string;
		page_number?: string;
		total_results?: string;
	};
}

export interface RecipeSummary {
	recipe_id: string;
	recipe_name: string;
	recipe_description?: string;
	recipe_url: string;
	recipe_image?: string;
}

export interface UserProfile {
	profile?: {
		user_id: string;
		height_measure?: string;
		weight_measure?: string;
		last_weight_kg?: string;
		goal_weight_kg?: string;
	};
}

export interface FoodEntry {
	food_entry_id: string;
	food_entry_description: string;
	food_id: string;
	serving_id: string;
	number_of_units: string;
	meal: string;
	calories: string;
	carbohydrate: string;
	protein: string;
	fat: string;
}

export interface WeightEntry {
	date_int: string;
	weight_kg: string;
	weight_comment?: string;
}

// ============================================================================
// Session Data Types
// ============================================================================

export interface SessionData {
	// FatSecret API credentials (shared key, separate secrets)
	clientId: string;
	clientSecret: string; // OAuth 2.0 Client Secret
	consumerSecret?: string; // OAuth 1.0a Consumer Secret (different from clientSecret)
	// Profile API (two-legged OAuth)
	profileId?: string;
	// OAuth 1.0a tokens (for user data - food diary, weight, etc.)
	accessToken?: string;
	accessTokenSecret?: string;
	userId?: string;
	// OAuth 2.0 cached token (for public data - search foods/recipes)
	oauth2AccessToken?: string;
	oauth2ExpiresAt?: number;
	// Metadata
	createdAt: number;
}

export interface OAuthState {
	sessionToken: string;
	requestToken: string;
	requestTokenSecret: string;
	createdAt: number;
}
