/**
 * Shared types and enums for FatSecret MCP Server
 */
import { z } from "zod";

// ============================================================================
// Enums
// ============================================================================

export const MealTypeEnum = z.enum(["breakfast", "lunch", "dinner", "snack"]);
export type MealType = z.infer<typeof MealTypeEnum>;

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
