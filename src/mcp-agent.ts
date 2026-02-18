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

// Props passed from auth middleware
export interface Props extends Record<string, unknown> {
	sessionToken: string;
	baseUrl?: string;
}

// Define our MCP agent with FatSecret API tools
export class FatSecretMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "FatSecret API",
		version: "0.2.0",
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

		this.server.tool(
			"search_foods",
			{
				searchExpression: z
					.string()
					.describe('Search term for foods (e.g., "chicken breast", "apple")'),
				pageNumber: z.number().optional().describe("Page number (default: 0)"),
				maxResults: z
					.number()
					.optional()
					.describe("Max results per page (default: 20, max: 50)"),
			},
			async ({ searchExpression, pageNumber, maxResults }) => {
				try {
					const response = await this.client.searchFoods(
						searchExpression,
						pageNumber ?? 0,
						maxResults ?? 20,
					);

					const totalResults = response.foods?.total_results || 0;

					return {
						content: [
							{
								type: "text",
								text: `Found ${totalResults} foods matching "${searchExpression}"`,
							},
							{
								type: "text",
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.tool(
			"get_food",
			{
				foodId: z.string().describe("The FatSecret food ID"),
			},
			async ({ foodId }) => {
				try {
					const response = await this.client.getFood(foodId);

					const food = response.food;
					const foodName = food?.food_name || "Unknown";

					return {
						content: [
							{
								type: "text",
								text: `Food: ${foodName}`,
							},
							{
								type: "text",
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

		this.server.tool(
			"search_recipes",
			{
				searchExpression: z.string().describe("Search term for recipes"),
				pageNumber: z.number().optional().describe("Page number (default: 0)"),
				maxResults: z
					.number()
					.optional()
					.describe("Max results per page (default: 20, max: 50)"),
			},
			async ({ searchExpression, pageNumber, maxResults }) => {
				try {
					const response = await this.client.searchRecipes(
						searchExpression,
						pageNumber ?? 0,
						maxResults ?? 20,
					);

					const totalResults = response.recipes?.total_results || 0;

					return {
						content: [
							{
								type: "text",
								text: `Found ${totalResults} recipes matching "${searchExpression}"`,
							},
							{
								type: "text",
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.tool(
			"get_recipe",
			{
				recipeId: z.string().describe("The FatSecret recipe ID"),
			},
			async ({ recipeId }) => {
				try {
					const response = await this.client.getRecipe(recipeId);

					const recipe = response.recipe;
					const recipeName = recipe?.recipe_name || "Unknown";

					return {
						content: [
							{
								type: "text",
								text: `Recipe: ${recipeName}`,
							},
							{
								type: "text",
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

		this.server.tool("get_user_profile", {}, async () => {
			try {
				const response = await this.client.getUserProfile();

				return {
					content: [
						{
							type: "text",
							text: "User Profile",
						},
						{
							type: "text",
							text: JSON.stringify(response, null, 2),
						},
					],
				};
			} catch (error) {
				return handleError(error);
			}
		});

		this.server.tool(
			"get_user_food_entries",
			{
				date: z
					.string()
					.optional()
					.describe("Date in YYYY-MM-DD format (default: today)"),
			},
			async ({ date }) => {
				try {
					const response = await this.client.getFoodEntries(date);

					const entries = response.food_entries?.food_entry;
					const entryCount = Array.isArray(entries)
						? entries.length
						: entries
							? 1
							: 0;

					return {
						content: [
							{
								type: "text",
								text: `Found ${entryCount} food entries for ${date || "today"}`,
							},
							{
								type: "text",
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.tool(
			"add_food_entry",
			{
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
								type: "text",
								text: `Food entry added successfully!`,
							},
							{
								type: "text",
								text: JSON.stringify(response, null, 2),
							},
						],
					};
				} catch (error) {
					return handleError(error);
				}
			},
		);

		this.server.tool(
			"get_weight_month",
			{
				date: z
					.string()
					.optional()
					.describe(
						"Date in YYYY-MM-DD format to specify the month (default: current month)",
					),
			},
			async ({ date }) => {
				try {
					const response = await this.client.getWeightMonth(date);

					const weights = response.month?.day;
					const entryCount = Array.isArray(weights)
						? weights.length
						: weights
							? 1
							: 0;

					return {
						content: [
							{
								type: "text",
								text: `Found ${entryCount} weight entries`,
							},
							{
								type: "text",
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

		this.server.tool("check_auth_status", {}, async () => {
			return {
				content: [
					{
						type: "text",
						text: `Authentication Status: Fully authenticated\n\nYou can use all FatSecret API tools.`,
					},
				],
			};
		});
	}
}
