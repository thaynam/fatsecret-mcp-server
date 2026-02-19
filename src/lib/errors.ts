/**
 * Error handling utilities for FatSecret MCP Server
 */
import { ZodError } from "zod";

/**
 * MCP Tool Response type
 */
export interface McpToolResponse {
  [x: string]: unknown;
  content: Array<{
    type: "text";
    text: string;
  }>;
  isError?: boolean;
}

/**
 * Custom error class for FatSecret API errors
 */
export class FatSecretApiError extends Error {
  status: number;
  data?: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = "FatSecretApiError";
    this.status = status;
    this.data = data;
  }
}

/**
 * HTTP status code to user-friendly message mapping
 */
const STATUS_CODE_MESSAGES: Record<number, string> = {
  400: "Invalid request parameters",
  401: "Unauthorized - Invalid OAuth credentials",
  403: "Access denied or OAuth signature invalid",
  404: "Resource not found",
  429: "Rate limit exceeded",
  500: "FatSecret API error",
  502: "FatSecret API is temporarily unavailable",
  503: "FatSecret API is temporarily unavailable",
};

/**
 * Get a user-friendly message for an HTTP status code
 */
function getStatusMessage(status: number): string {
  return STATUS_CODE_MESSAGES[status] || `Unexpected error (HTTP ${status})`;
}

/**
 * Format a FatSecret API error into a user-friendly MCP tool response
 */
function formatFatSecretApiError(error: FatSecretApiError): McpToolResponse {
  const statusMessage = getStatusMessage(error.status);
  const parts: string[] = [];

  parts.push(`Error: ${statusMessage}`);
  parts.push("");
  parts.push("**What went wrong:**");
  parts.push(error.message);

  // Add API-specific details if available
  if (error.data) {
    if (typeof error.data === "string") {
      parts.push("");
      parts.push("**Details:**");
      parts.push(error.data);
    } else if (typeof error.data === "object") {
      const errorData = error.data as Record<string, Record<string, string>>;

      if (errorData.error) {
        parts.push("");
        parts.push("**API Error:**");
        if (errorData.error.code) {
          parts.push(`Code: ${errorData.error.code}`);
        }
        if (errorData.error.message) {
          parts.push(`Message: ${errorData.error.message}`);
        }
      }
    }
  }

  // Add actionable advice based on status code
  parts.push("");
  parts.push("**How to fix:**");

  switch (error.status) {
    case 400:
      parts.push("  - Check that all required parameters are provided");
      parts.push(
        "  - Verify parameter formats (dates as YYYY-MM-DD, IDs as strings)",
      );
      parts.push("  - Ensure all values are within valid ranges");
      break;

    case 401:
      parts.push("  - Verify your FatSecret API credentials are correct");
      parts.push("  - Complete the OAuth flow to get access tokens");
      parts.push("  - Check that your access token has not expired");
      break;

    case 403:
      parts.push("  - The OAuth signature may be invalid");
      parts.push("  - Re-authenticate using the OAuth flow");
      parts.push("  - Verify your API credentials are correct");
      break;

    case 404:
      parts.push(
        "  - Verify the resource ID exists (food_id, recipe_id, etc.)",
      );
      parts.push("  - Check for typos in the ID");
      parts.push("  - Use search tools to find valid IDs");
      break;

    case 429:
      parts.push("  - Wait before making more requests");
      parts.push("  - FatSecret has rate limits on API calls");
      parts.push("  - Try again in a few moments");
      break;

    case 500:
    case 502:
    case 503:
      parts.push("  - This is a temporary FatSecret API issue");
      parts.push("  - Try again in a few moments");
      parts.push("  - If the problem persists, check FatSecret status");
      break;

    default:
      parts.push("  - Review the error details above");
      parts.push("  - Consult the FatSecret API documentation");
      parts.push("  - Contact FatSecret support if the issue persists");
  }

  return {
    content: [
      {
        type: "text",
        text: parts.join("\n"),
      },
    ],
    isError: true,
  };
}

/**
 * Format a Zod validation error into a user-friendly MCP tool response
 */
function formatValidationError(error: ZodError): McpToolResponse {
  const parts: string[] = [];

  parts.push("Error: Schema Validation Failed");
  parts.push("");
  parts.push("**What went wrong:**");
  parts.push("The provided data does not match the expected format.");
  parts.push("");

  // Group errors by path for better readability
  const errorsByPath = new Map<string, string[]>();

  for (const issue of error.errors) {
    const path = issue.path.length > 0 ? issue.path.join(".") : "root";
    const messages = errorsByPath.get(path) || [];
    messages.push(issue.message);
    errorsByPath.set(path, messages);
  }

  parts.push("**Validation Issues:**");
  for (const [path, messages] of errorsByPath.entries()) {
    if (path === "root") {
      for (const message of messages) {
        parts.push(`  - ${message}`);
      }
    } else {
      parts.push(`  - **${path}**:`);
      for (const message of messages) {
        parts.push(`    ${message}`);
      }
    }
  }

  parts.push("");
  parts.push("**How to fix:**");
  parts.push("  - Review the validation issues listed above");
  parts.push("  - Ensure all required fields are provided");
  parts.push("  - Check that field types match expected types");

  return {
    content: [
      {
        type: "text",
        text: parts.join("\n"),
      },
    ],
    isError: true,
  };
}

/**
 * Safe error logger that avoids leaking sensitive data
 */
export function safeLogError(context: string, error: unknown): void {
  const message = error instanceof Error ? error.message : "Unknown error";
  console.error(`${context}: ${message}`);
}

/**
 * Central error handler that routes errors to appropriate formatters
 */
export function handleError(error: unknown): McpToolResponse {
  // Handle FatSecret API errors
  if (error instanceof FatSecretApiError) {
    return formatFatSecretApiError(error);
  }

  // Handle Zod validation errors
  if (error instanceof ZodError) {
    return formatValidationError(error);
  }

  // Handle generic errors
  if (error instanceof Error) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error.message}`,
        },
      ],
      isError: true,
    };
  }

  // Handle unknown error types
  return {
    content: [
      {
        type: "text",
        text: "An unknown error occurred",
      },
    ],
    isError: true,
  };
}
