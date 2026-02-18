/**
 * Utility Routes
 *
 * Health check, home page, setup page, and credential management.
 */

import { Hono } from "hono";
import { FatSecretClient } from "../lib/client.js";
import {
	getSession,
	storeSession,
	generateSessionToken,
	maskSecret,
} from "../lib/token-storage.js";
import { escapeHtml } from "../lib/transforms.js";
import type { SessionData } from "../lib/schemas.js";

const utilityRoutes = new Hono<{ Bindings: Env }>();

/**
 * GET /health
 */
utilityRoutes.get("/health", (c) => {
	return c.json({
		status: "healthy",
		service: "fatsecret-mcp-server",
		version: "0.2.0",
		timestamp: new Date().toISOString(),
	});
});

/**
 * GET / - Home page
 */
utilityRoutes.get("/", (c) => {
	return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FatSecret MCP Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; min-height: 100vh; padding: 2rem; background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); }
        .container { max-width: 900px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); color: white; padding: 3rem 2rem; text-align: center; }
        .header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        .setup-section { padding: 3rem 2rem; text-align: center; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
        .setup-section h2 { font-size: 1.5rem; color: #1e293b; margin-bottom: 1rem; }
        .setup-section p { color: #64748b; margin-bottom: 2rem; font-size: 1.1rem; }
        .setup-button { display: inline-block; background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); color: white; padding: 1rem 3rem; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 1.1rem; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(34, 197, 94, 0.4); }
        .setup-button:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(34, 197, 94, 0.6); }
        .features { padding: 3rem 2rem; }
        .features h2 { font-size: 1.8rem; color: #1e293b; margin-bottom: 2rem; text-align: center; }
        .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 2rem; }
        .feature { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05); border: 1px solid #e2e8f0; }
        .feature h3 { font-size: 1.2rem; color: #1e293b; margin-bottom: 1rem; }
        .feature p { color: #64748b; font-size: 0.95rem; }
        .footer { background: #1e293b; color: #94a3b8; padding: 2rem; text-align: center; font-size: 0.9rem; }
        .footer a { color: #22c55e; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>FatSecret MCP Server</h1>
            <p style="opacity: 0.9; margin-top: 0.5rem;">AI-powered nutrition tracking via MCP</p>
        </div>
        <div class="setup-section">
            <h2>Get Started</h2>
            <p>Connect your FatSecret API for AI-powered nutrition tracking.</p>
            <a href="/setup" class="setup-button">Setup Your Account</a>
        </div>
        <div class="features">
            <h2>What You Can Do</h2>
            <div class="feature-grid">
                <div class="feature"><h3>Search Foods</h3><p>Search millions of foods with nutritional information.</p></div>
                <div class="feature"><h3>Find Recipes</h3><p>Discover recipes with detailed nutrition breakdowns.</p></div>
                <div class="feature"><h3>Track Your Diet</h3><p>Log food entries to your FatSecret diary.</p></div>
                <div class="feature"><h3>Monitor Weight</h3><p>Track your weight progress over time.</p></div>
            </div>
        </div>
        <div class="footer">
            <p>Built using <a href="https://modelcontextprotocol.io/">MCP</a> and <a href="https://developers.cloudflare.com/workers/">Cloudflare Workers</a></p>
        </div>
    </div>
</body>
</html>`);
});

/**
 * GET /setup - Setup page
 */
utilityRoutes.get("/setup", async (c) => {
	const sessionCookie = c.req.header("Cookie");
	const sessionToken = sessionCookie?.match(/fatsecret_session=([^;]+)/)?.[1];

	// Get query params for error/success messages
	const url = new URL(c.req.url);
	const errorType = url.searchParams.get("error");
	const errorMessage = url.searchParams.get("message");
	const success = url.searchParams.get("success");

	let session: SessionData | null = null;
	if (sessionToken) {
		session = await getSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
		);
	}

	const hasCredentials = !!session;
	const hasUserAuth = !!(session?.accessToken && session?.accessTokenSecret);
	const baseUrl = url.origin;

	// Build alert message HTML
	let alertHtml = "";
	if (errorType) {
		const msg = errorMessage
			? escapeHtml(decodeURIComponent(errorMessage))
			: getErrorMessage(errorType);
		alertHtml = `<div class="alert alert-error">${msg}</div>`;
	} else if (success === "connected") {
		alertHtml = `<div class="alert alert-success">FatSecret account connected successfully!</div>`;
	}

	function getErrorMessage(type: string): string {
		switch (type) {
			case "no_session":
				return "No session found. Please enter your credentials first.";
			case "invalid_session":
				return "Session expired. Please enter your credentials again.";
			case "oauth_failed":
				return "OAuth flow failed. Please try again.";
			default:
				return "An error occurred. Please try again.";
		}
	}

	const credentialsSection = !hasCredentials
		? `<div class="section">
            <h3>Step 1: Enter API Credentials</h3>
            <form id="credentialsForm">
                <label>Client ID</label>
                <div class="help-text">Get credentials from <a href="https://platform.fatsecret.com/api/" target="_blank">FatSecret Platform API</a></div>
                <input type="text" id="clientId" placeholder="Your Client ID" required>
                <label>Client Secret <span style="font-weight:normal;color:#888;">(OAuth 2.0)</span></label>
                <input type="password" id="clientSecret" placeholder="Your Client Secret" required>
                <label>Consumer Secret <span style="font-weight:normal;color:#888;">(OAuth 1.0 REST API)</span></label>
                <div class="help-text">Found under "REST API OAuth 1.0 Credentials" on the developer portal</div>
                <input type="password" id="consumerSecret" placeholder="Your Consumer Secret" required>
                <div class="button-group"><button type="submit" class="btn-primary">Save Credentials</button></div>
            </form>
        </div>`
		: `<div class="section">
            <h3>Your Session Token</h3>
            <p style="font-size:14px;color:#666;margin-bottom:10px;">Use this token to configure your MCP client:</p>
            <div class="token-display" id="tokenDisplay">${escapeHtml(sessionToken!)}</div>
            <button class="copy-btn" onclick="copyToken()">Copy Token</button>
        </div>
        ${
					!hasUserAuth
						? `<div class="section">
            <h3>Step 2: Connect Your Account</h3>
            <p style="font-size:14px;color:#666;margin-bottom:15px;">Choose how to set up food diary access:</p>
            <a href="/oauth/connect-account" class="btn btn-primary" style="display:block;margin-bottom:10px;">Connect Existing FatSecret Account</a>
            <p style="font-size:12px;color:#888;text-align:center;margin:8px 0;">Links to your existing food diary &amp; weight data. Requires a <a href="https://www.fatsecret.com" target="_blank">fatsecret.com</a> account (not the developer portal).</p>
            <hr style="margin:15px 0;border:none;border-top:1px solid #eee;">
            <a href="/oauth/connect" class="btn" style="display:block;background:#6c757d;color:white;padding:10px;text-align:center;border-radius:5px;text-decoration:none;">Create New Profile Instead</a>
            <p style="font-size:12px;color:#888;text-align:center;margin:8px 0;">Starts fresh — no login required, but won't have your existing data.</p>
        </div>`
						: ""
				}
        <div class="section">
            <h3>MCP Configuration</h3>
            <div class="config-example">{
  "mcpServers": {
    "fatsecret": {
      "url": "${escapeHtml(baseUrl)}/mcp",
      "transport": {
        "type": "http",
        "headers": {
          "Authorization": "Bearer ${escapeHtml(sessionToken!)}"
        }
      }
    }
  }
}</div>
            <button class="copy-btn" onclick="copyConfig()">Copy Configuration</button>
        </div>
        <div style="margin-top:20px;padding-top:20px;border-top:1px solid #e0e0e0;">
            <button id="deleteBtn" class="btn-danger" style="width:100%;">Delete Credentials</button>
        </div>`;

	const statusHtml = hasCredentials
		? `<div class="status configured"><span class="status-icon">OK</span><div><strong>API Configured</strong><div style="font-size:14px;margin-top:4px;">Client: ${escapeHtml(maskSecret(session!.clientId))}</div></div></div>`
		: `<div class="status not-configured"><span class="status-icon">!</span><div><strong>Not Configured</strong></div></div>`;

	const userAuthStatus =
		hasCredentials && !hasUserAuth
			? `<div class="status not-configured"><span class="status-icon">~</span><div><strong>Account Not Connected</strong></div></div>`
			: hasUserAuth
				? `<div class="status connected"><span class="status-icon">+</span><div><strong>Account Connected</strong><div style="font-size:14px;margin-top:4px;">User: ${escapeHtml(session!.userId || "OK")}</div></div></div>`
				: "";

	c.header("Cache-Control", "no-store");
	return c.html(`<!DOCTYPE html>
<html><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FatSecret Setup</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 600px; width: 100%; padding: 40px; }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .subtitle { color: #666; margin-bottom: 30px; }
        .status { padding: 15px; border-radius: 8px; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
        .status.configured { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.not-configured { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .status.connected { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .status-icon { font-size: 24px; font-weight: bold; }
        .section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section h3 { margin-bottom: 15px; color: #333; }
        label { display: block; font-weight: 600; margin-bottom: 8px; color: #333; }
        .help-text { font-size: 14px; color: #666; margin-bottom: 8px; }
        .help-text a { color: #22c55e; }
        input { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 6px; font-size: 14px; font-family: monospace; margin-bottom: 15px; }
        input:focus { outline: none; border-color: #22c55e; }
        .button-group { display: flex; gap: 10px; margin-top: 20px; }
        button, .btn { flex: 1; padding: 12px 24px; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; text-decoration: none; text-align: center; display: inline-block; }
        .btn-primary { background: #22c55e; color: white; }
        .btn-primary:hover { background: #16a34a; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        button:disabled { opacity: 0.6; cursor: not-allowed; }
        .message { padding: 12px; border-radius: 6px; margin-bottom: 20px; display: none; }
        .message.success { background: #d4edda; color: #155724; }
        .message.error { background: #f8d7da; color: #721c24; }
        .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #22c55e; border-radius: 50%; width: 20px; height: 20px; animation: spin 0.8s linear infinite; display: inline-block; margin-left: 10px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .token-display { background: #f4f4f4; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 12px; word-break: break-all; margin: 15px 0; }
        .config-example { background: #1e293b; color: #e2e8f0; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 13px; overflow-x: auto; white-space: pre; }
        .copy-btn { background: #4b5563; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>FatSecret MCP Setup</h1>
        <p class="subtitle">Configure your FatSecret API credentials</p>
        ${alertHtml}
        ${statusHtml}
        ${userAuthStatus}
        <div id="message" class="message"></div>
        ${credentialsSection}
    </div>
    <script>
        const message = document.getElementById('message');
        function showMessage(text, type) {
            message.textContent = text;
            message.className = 'message ' + type;
            message.style.display = 'block';
            setTimeout(() => { message.style.display = 'none'; }, 5000);
        }
        function copyToken() {
            navigator.clipboard.writeText(document.getElementById('tokenDisplay')?.textContent || '');
            showMessage('Token copied!', 'success');
        }
        function copyConfig() {
            navigator.clipboard.writeText(document.querySelector('.config-example')?.textContent || '');
            showMessage('Configuration copied!', 'success');
        }
        ${
					!hasCredentials
						? `
        document.getElementById('credentialsForm')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = e.target.querySelector('button');
            btn.disabled = true;
            btn.innerHTML = 'Saving...<span class="spinner"></span>';
            try {
                const response = await fetch('/api/save-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        clientId: document.getElementById('clientId').value,
                        clientSecret: document.getElementById('clientSecret').value,
                        consumerSecret: document.getElementById('consumerSecret').value,
                    }),
                });
                const data = await response.json();
                if (response.ok) {
                    showMessage('Saved!', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showMessage(data.error || 'Failed', 'error');
                }
            } catch (error) {
                showMessage('Error: ' + error.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Save Credentials';
            }
        });`
						: `
        document.getElementById('deleteBtn')?.addEventListener('click', async () => {
            if (!confirm('Delete credentials?')) return;
            await fetch('/api/delete-credentials', { method: 'DELETE' });
            location.reload();
        });`
				}
    </script>
</body>
</html>`);
});

/**
 * POST /api/save-credentials
 */
utilityRoutes.post("/api/save-credentials", async (c) => {
	try {
		const { clientId, clientSecret, consumerSecret } = await c.req.json();
		if (!clientId || !clientSecret) {
			return c.json({ error: "Client ID and Client Secret are required" }, 400);
		}

		const client = new FatSecretClient({ clientId, clientSecret });
		if (!(await client.validateCredentials())) {
			return c.json(
				{ error: "Invalid OAuth 2.0 credentials (Client ID / Client Secret)" },
				400,
			);
		}

		const sessionToken = generateSessionToken();
		const sessionData: SessionData = {
			clientId,
			clientSecret,
			consumerSecret: consumerSecret || undefined,
			createdAt: Date.now(),
		};
		await storeSession(
			c.env.OAUTH_KV,
			c.env.COOKIE_ENCRYPTION_KEY,
			sessionToken,
			sessionData,
		);

		const response = c.json({ success: true, sessionToken });
		response.headers.set(
			"Set-Cookie",
			`fatsecret_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}`,
		);
		return response;
	} catch (error) {
		console.error("Save credentials error:", error);
		return c.json({ error: "Failed to save credentials" }, 500);
	}
});

/**
 * DELETE /api/delete-credentials
 */
utilityRoutes.delete("/api/delete-credentials", async (c) => {
	const sessionToken = c.req
		.header("Cookie")
		?.match(/fatsecret_session=([^;]+)/)?.[1];
	if (sessionToken) await c.env.OAUTH_KV.delete(`session:${sessionToken}`);
	const response = c.json({ success: true });
	response.headers.set("Set-Cookie", "fatsecret_session=; Path=/; Max-Age=0");
	return response;
});

export default utilityRoutes;
