/**
 * Shared constants for the FatSecret MCP Server
 */

// TTL values (in seconds)
export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
export const OAUTH_STATE_TTL_SECONDS = 10 * 60; // 10 minutes
export const OAUTH2_CLIENT_TTL_SECONDS = 90 * 24 * 60 * 60; // 90 days
export const OAUTH2_CODE_TTL_SECONDS = 10 * 60; // 10 minutes
export const OAUTH2_TOKEN_BUFFER_MS = 5 * 60 * 1000; // 5 minutes

// Input validation limits
export const MAX_CREDENTIAL_LENGTH = 500;
export const MAX_TOKEN_LENGTH = 200;
export const MAX_REDIRECT_URI_LENGTH = 2000;
export const MAX_REDIRECT_URIS = 10;
export const MAX_CALLBACK_URL_LENGTH = 2000;

// Text truncation limits
export const MAX_ERROR_TEXT_LENGTH = 200;
export const MAX_RAW_RESPONSE_LENGTH = 500;
