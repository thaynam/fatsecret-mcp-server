/**
 * Setup page view
 */

import { escapeHtml } from "../lib/transforms.js";

export interface SetupPageParams {
	hasCredentials: boolean;
	hasUserAuth: boolean;
	sessionToken: string | null;
	baseUrl: string;
	maskedClientId: string;
	userId: string;
	alertHtml: string;
}

export function renderSetupPage(params: SetupPageParams): string {
	const {
		hasCredentials,
		hasUserAuth,
		sessionToken,
		baseUrl,
		maskedClientId,
		userId,
		alertHtml,
	} = params;

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
			<div class="token-display" id="tokenDisplay">${escapeHtml(sessionToken || "")}</div>
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
          "Authorization": "Bearer ${escapeHtml(sessionToken || "")}"
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
		? `<div class="status configured"><span class="status-icon">OK</span><div><strong>API Configured</strong><div style="font-size:14px;margin-top:4px;">Client: ${escapeHtml(maskedClientId)}</div></div></div>`
		: `<div class="status not-configured"><span class="status-icon">!</span><div><strong>Not Configured</strong></div></div>`;

	const userAuthStatus =
		hasCredentials && !hasUserAuth
			? `<div class="status not-configured"><span class="status-icon">~</span><div><strong>Account Not Connected</strong></div></div>`
			: hasUserAuth
				? `<div class="status connected"><span class="status-icon">+</span><div><strong>Account Connected</strong><div style="font-size:14px;margin-top:4px;">User: ${escapeHtml(userId)}</div></div></div>`
				: "";

	const scriptContent = !hasCredentials
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
		});`;

	return `<!DOCTYPE html>
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
		${scriptContent}
	</script>
</body>
</html>`;
}
