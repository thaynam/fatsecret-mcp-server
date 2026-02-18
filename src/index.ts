/**
 * FatSecret MCP Server - Entry Point
 *
 * Cloudflare Workers entry point that exports the Hono app and Durable Object.
 */

// Export Hono app as default
import app from "./app.js";
export default app;

// Export Durable Object
export { FatSecretMCP } from "./mcp-agent.js";
