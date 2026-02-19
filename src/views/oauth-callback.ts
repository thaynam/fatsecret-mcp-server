/**
 * OAuth callback views
 */

import { escapeHtml } from "../lib/transforms.js";

export function renderVerifierForm(): string {
	return `
		<!DOCTYPE html>
		<html>
		<head>
			<title>FatSecret OAuth - Enter Verifier</title>
			<style>
				body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
				input, button { font-size: 16px; padding: 10px; margin: 5px 0; }
				input { width: 100%; box-sizing: border-box; }
				button { background: #007bff; color: white; border: none; cursor: pointer; }
				button:hover { background: #0056b3; }
			</style>
		</head>
		<body>
			<h1>FatSecret OAuth</h1>
			<p>Enter the verifier code from FatSecret:</p>
			<form method="GET" action="/oauth/callback">
				<input type="text" name="state" placeholder="State token from /oauth/setup" required>
				<input type="text" name="oauth_verifier" placeholder="Verifier code" required>
				<button type="submit">Complete Authentication</button>
			</form>
		</body>
		</html>
	`;
}

export function renderOAuthSuccess(params: {
	sessionToken: string;
	origin: string;
	userId: string;
}): string {
	return `
		<!DOCTYPE html>
		<html>
		<head>
			<title>FatSecret OAuth - Success</title>
			<style>
				body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
				.token { background: #f0f0f0; padding: 15px; border-radius: 5px; word-break: break-all; font-family: monospace; }
				.copy-btn { margin-top: 10px; padding: 8px 16px; cursor: pointer; }
			</style>
		</head>
		<body>
			<h1>Authentication Successful!</h1>
			<p>Your FatSecret account is now connected. Use this token as a Bearer token in your MCP client:</p>
			<div class="token" id="token">${escapeHtml(params.sessionToken)}</div>
			<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('token').textContent)">Copy Token</button>
			<h2>MCP Configuration</h2>
			<p>Add this to your MCP client configuration:</p>
			<pre style="background: #f0f0f0; padding: 15px; border-radius: 5px; overflow-x: auto;">
{
  "mcpServers": {
    "fatsecret": {
      "url": "${escapeHtml(params.origin)}/mcp",
      "transport": {
        "type": "http",
        "headers": {
          "Authorization": "Bearer ${escapeHtml(params.sessionToken)}"
        }
      }
    }
  }
}</pre>
			<p><strong>User ID:</strong> ${escapeHtml(params.userId)}</p>
		</body>
		</html>
	`;
}

export function renderOAuthError(): string {
	return `
		<!DOCTYPE html>
		<html>
		<head><title>OAuth Error</title></head>
		<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
			<h1>Authentication Failed</h1>
			<p>Authentication could not be completed. Please try again.</p>
			<p><a href="/">Try again</a></p>
		</body>
		</html>
	`;
}
