/**
 * FatSecret MCP Agent
 *
 * Defines the MCP server with all FatSecret API tools.
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { FatSecretClient } from "./lib/client.js";
import { handleError } from "./lib/errors.js";
import { getSession } from "./lib/token-storage.js";
import { APP_VERSION } from "./app.js";

// biome-ignore lint/suspicious/noExplicitAny: FatSecret API responses have dynamic shapes
type ApiResponse = Record<string, any>;

// Props passed from auth middleware
export interface Props extends Record<string, unknown> {
	sessionToken: string;
	baseUrl?: string;
}

// Define our MCP agent with FatSecret API tools
export class FatSecretMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "FatSecret API",
		version: APP_VERSION,
	});

	private client!: FatSecretClient;

	async init() {
		// Check if user is authenticated
		if (!this.props || !this.props.sessionToken) {
			const setupHint = this.props?.baseUrl
				? ` Visit ${this.props.baseUrl} to get started.`
				: " Visit your server URL to authenticate.";
			throw new Error(
				"Authentication required. Please authenticate via OAuth to use the FatSecret MCP server." +
					setupHint,
			);
		}

		// Load user's session data from encrypted KV storage
		const sessionData = await getSession(
			this.env.OAUTH_KV,
			this.env.COOKIE_ENCRYPTION_KEY,
			this.props.sessionToken,
		);

		if (!sessionData) {
			const setupUrl = this.props.baseUrl || "/";
			throw new Error(
				`Session not found or expired. Please visit ${setupUrl} to authenticate again.`,
			);
		}

		if (!sessionData.accessToken || !sessionData.accessTokenSecret) {
			const setupUrl = this.props.baseUrl
				? `${this.props.baseUrl}/oauth/start`
				: "/oauth/start";
			throw new Error(
				`OAuth not completed. Please visit ${setupUrl} to complete authentication.`,
			);
		}

		// Initialize FatSecret API client with user-specific credentials
		this.client = new FatSecretClient({
			clientId: sessionData.clientId,
			clientSecret: sessionData.clientSecret,
			consumerSecret: sessionData.consumerSecret,
			accessToken: sessionData.accessToken,
			accessTokenSecret: sessionData.accessTokenSecret,
		});

		// ============================================
		// FOOD DATABASE TOOLS
		// ============================================

		this.server.registerTool(
			"search_foods",
			{
				description: "Search for foods in the FatSecret nutrition database",
				inputSchema: {
					searchExpression: z
						.string()
						.describe('Search term for foods (e.g., "chicken breast", "apple")'),
					pageNumber: z.number().optional().describe("Page number (default: 0)"),
					maxResults: z
						.number()
						.optional()
						.describe("Max results per page (default: 20, max: 50)"),
				},
			},
			async ({ searchExpression, pageNumber, maxResults }) => {
				try {
					const response = (await this.client.searchFoods(
						searchExpression,
						pageNumber ?? 0,
						maxResults ?? 20,
					)) as ApiResponse;

					const totalResults = response.foods?.total_results || 0;

					return {
						content: [
							{
								type: "text" as const,
								text: `Found ${totalResults} foods matching "${searchExpression}"`,
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.registerTool(
			"get_food",
			{
				description: "Get detailed nutritional information for a specific food",
				inputSchema: {
					foodId: z.string().describe("The FatSecret food ID"),
				},
			},
			async ({ foodId }) => {
				try {
					const response = (await this.client.getFood(foodId)) as ApiResponse;

					const food = response.food;
					const foodName = food?.food_name || "Unknown";

					return {
						content: [
							{
								type: "text" as const,
								text: `Food: ${foodName}`,
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		// ============================================
		// RECIPE DATABASE TOOLS
		// ============================================

		this.server.registerTool(
			"search_recipes",
			{
				description: "Search for recipes in the FatSecret database",
				inputSchema: {
					searchExpression: z.string().describe("Search term for recipes"),
					pageNumber: z.number().optional().describe("Page number (default: 0)"),
					maxResults: z
						.number()
						.optional()
						.describe("Max results per page (default: 20, max: 50)"),
				},
			},
			async ({ searchExpression, pageNumber, maxResults }) => {
				try {
					const response = (await this.client.searchRecipes(
						searchExpression,
						pageNumber ?? 0,
						maxResults ?? 20,
					)) as ApiResponse;

					const totalResults = response.recipes?.total_results || 0;

					return {
						content: [
							{
								type: "text" as const,
								text: `Found ${totalResults} recipes matching "${searchExpression}"`,
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.registerTool(
			"get_recipe",
			{
				description: "Get detailed information about a specific recipe",
				inputSchema: {
					recipeId: z.string().describe("The FatSecret recipe ID"),
				},
			},
			async ({ recipeId }) => {
				try {
					const response = (await this.client.getRecipe(
						recipeId,
					)) as ApiResponse;

					const recipe = response.recipe;
					const recipeName = recipe?.recipe_name || "Unknown";

					return {
						content: [
							{
								type: "text" as const,
								text: `Recipe: ${recipeName}`,
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		// ============================================
		// USER DATA TOOLS (Require OAuth)
		// ============================================

		this.server.registerTool(
			"get_user_profile",
			{
				description: "Get the authenticated user's FatSecret profile",
			},
			async () => {
				try {
					const response = await this.client.getUserProfile();

					return {
						content: [
							{
								type: "text" as const,
								text: "User Profile",
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.registerTool(
			"get_user_food_entries",
			{
				description: "Get food diary entries for a specific date",
				inputSchema: {
					date: z
						.string()
						.optional()
						.describe("Date in YYYY-MM-DD format (default: today)"),
				},
			},
			async ({ date }) => {
				try {
					const response = (await this.client.getFoodEntries(
						date,
					)) as ApiResponse;

					const entries = response.food_entries?.food_entry;
					const entryCount = Array.isArray(entries)
						? entries.length
						: entries
							? 1
							: 0;

					return {
						content: [
							{
								type: "text" as const,
								text: `Found ${entryCount} food entries for ${date || "today"}`,
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.registerTool(
			"add_food_entry",
			{
				description: "Add a food entry to the user's food diary",
				inputSchema: {
					foodId: z.string().describe("The FatSecret food ID"),
					servingId: z.string().describe("The serving ID for the food"),
					quantity: z.number().describe("Quantity of the serving"),
					mealType: z
						.enum(["breakfast", "lunch", "dinner", "snack"])
						.describe("Meal type"),
					date: z
						.string()
						.optional()
						.describe("Date in YYYY-MM-DD format (default: today)"),
				},
			},
			async ({ foodId, servingId, quantity, mealType, date }) => {
				try {
					const response = await this.client.addFoodEntry(
						foodId,
						servingId,
						quantity,
						mealType,
						date,
					);

					return {
						content: [
							{
								type: "text" as const,
								text: "Food entry added successfully!",
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.registerTool(
			"get_weight_month",
			{
				description: "Get weight entries for a specific month",
				inputSchema: {
					date: z
						.string()
						.optional()
						.describe(
							"Date in YYYY-MM-DD format to specify the month (default: current month)",
						),
				},
			},
			async ({ date }) => {
				try {
					const response = (await this.client.getWeightMonth(
						date,
					)) as ApiResponse;

					const weights = response.month?.day;
					const entryCount = Array.isArray(weights)
						? weights.length
						: weights
							? 1
							: 0;

					return {
						content: [
							{
								type: "text" as const,
								text: `Found ${entryCount} weight entries`,
							},
							{
								type: "text" as const,
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		// ============================================
		// AUTH STATUS TOOL
		// ============================================

		this.server.registerTool(
			"check_auth_status",
			{
				description: "Check current authentication status",
			},
			async () => {
				return {
					content: [
						{
							type: "text" as const,
							text: "Authentication Status: Fully authenticated\n\nYou can use all FatSecret API tools.",
						},
					],
				};
			},
		);
	}
}
