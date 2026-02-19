/**
 * MCP Handler exports for Cloudflare Workers
 */

import { FatSecretMCP } from "./mcp-agent.js";

// Create MCP handlers
export const mcpHandlers = {
  streamableHTTP: FatSecretMCP.serve("/mcp", { binding: "MCP_OBJECT" }),
  sse: FatSecretMCP.serveSSE("/sse", { binding: "MCP_OBJECT" }),
};
