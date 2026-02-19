/**
 * MCP Handler exports for Cloudflare Workers
 */

import { FatSecretMCP } from "./mcp-agent.js";
import type { McpHandlers } from "./routes/mcp.js";

// Create MCP handlers
export const mcpHandlers: McpHandlers = {
	streamableHTTP: FatSecretMCP.serve("/mcp", { binding: "MCP_OBJECT" }),
	sse: FatSecretMCP.serveSSE("/sse", { binding: "MCP_OBJECT" }),
};
