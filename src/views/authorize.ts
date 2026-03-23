/**
 * OAuth 2.0 authorization page views
 */

import { escapeHtml } from "../lib/transforms.js";

/** Render the authorization page HTML */
export function renderAuthorizePage(params: {
	clientName?: string;
	hasSession: boolean;
	maskedClientId?: string;
	error?: string;
	// OAuth params to carry through as hidden fields
	clientId: string;
	redirectUri: string;
	state: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	scope: string;
}): string {
	const hiddenFields = `
		<input type="hidden" name="client_id" value="${escapeHtml(params.clientId)}">
		<input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
		<input type="hidden" name="state" value="${escapeHtml(params.state)}">
		<input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
		<input type="hidden" name="code_challenge_method" value="${escapeHtml(params.codeChallengeMethod)}">
		<input type="hidden" name="scope" value="${escapeHtml(params.scope)}">
	`;

	const errorHtml = params.error
		? `<div style="background:#fee;border:1px solid #fcc;padding:12px;border-radius:8px;margin-bottom:20px;color:#c33;">${escapeHtml(params.error)}</div>`
		: "";

	const appName = params.clientName || "An application";

	if (params.hasSession) {
		// Consent screen for existing session
		return `<!DOCTYPE html>
<html><head><title>Authorize - FatSecret MCP</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
	body{font-family:system-ui,sans-serif;max-width:480px;margin:40px auto;padding:20px;background:#f5f5f5;}
	.card{background:white;border-radius:12px;padding:30px;box-shadow:0 2px 8px rgba(0,0,0,0.1);}
	h1{font-size:20px;margin:0 0 8px;}
	.subtitle{color:#666;font-size:14px;margin-bottom:20px;}
	.permissions{background:#f8f9fa;border-radius:8px;padding:16px;margin:16px 0;}
	.permissions li{margin:6px 0;font-size:14px;}
	.identity{font-size:13px;color:#888;margin:16px 0;}
	.btn-group{display:flex;gap:10px;margin-top:20px;}
	.btn{flex:1;padding:12px;border:none;border-radius:8px;font-size:15px;cursor:pointer;font-weight:500;}
	.btn-allow{background:#22c55e;color:white;}
	.btn-allow:hover{background:#16a34a;}
	.btn-deny{background:#e5e7eb;color:#374151;}
	.btn-deny:hover{background:#d1d5db;}
</style></head><body>
<div class="card">
	<h1>Authorize Access</h1>
	<p class="subtitle"><strong>${escapeHtml(appName)}</strong> wants to access your FatSecret nutrition data.</p>
	${errorHtml}
	<div class="permissions">
		<strong style="font-size:14px;">This will allow:</strong>
		<ul>
			<li>Search foods and recipes</li>
			<li>Read your food diary</li>
			<li>Add food entries</li>
			<li>View weight data</li>
		</ul>
	</div>
	<div class="identity">Connected as: <code>${params.maskedClientId || "unknown"}</code></div>
	<form method="POST" action="/oauth2/authorize">
		${hiddenFields}
		<input type="hidden" name="action" value="allow">
		<div class="btn-group">
			<button type="submit" class="btn btn-allow">Allow</button>
			<button type="submit" name="action" value="deny" class="btn btn-deny">Deny</button>
		</div>
	</form>
</div>
</body></html>`;
	}

	// Credential entry form for new users
	return `<!DOCTYPE html>
<html><head><title>Connect & Authorize - FatSecret MCP</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
	body{font-family:system-ui,sans-serif;max-width:480px;margin:40px auto;padding:20px;background:#f5f5f5;}
	.card{background:white;border-radius:12px;padding:30px;box-shadow:0 2px 8px rgba(0,0,0,0.1);}
	h1{font-size:20px;margin:0 0 8px;}
	.subtitle{color:#666;font-size:14px;margin-bottom:20px;}
	label{display:block;font-size:14px;font-weight:500;margin:14px 0 4px;}
	.help{font-size:12px;color:#888;margin:2px 0 6px;}
	input[type="text"],input[type="password"]{width:100%;padding:10px;border:1px solid #ddd;border-radius:6px;font-size:14px;box-sizing:border-box;}
	input:focus{outline:none;border-color:#22c55e;box-shadow:0 0 0 2px rgba(34,197,94,0.15);}
	.btn{width:100%;padding:12px;border:none;border-radius:8px;font-size:15px;cursor:pointer;font-weight:500;margin-top:20px;background:#22c55e;color:white;}
	.btn:hover{background:#16a34a;}
</style></head><body>
<div class="card">
	<h1>Connect & Authorize</h1>
	<p class="subtitle"><strong>${escapeHtml(appName)}</strong> wants to access your FatSecret nutrition data. Enter your API credentials to connect.</p>
	${errorHtml}
	<form method="POST" action="/oauth2/authorize">
		${hiddenFields}
		<input type="hidden" name="action" value="credentials">
		<label>Client ID</label>
		<div class="help">From <a href="https://platform.fatsecret.com/api/" target="_blank">FatSecret Platform API</a></div>
		<input type="text" name="fs_client_id" placeholder="Your Client ID" required>
		<label>Client Secret <span style="font-weight:normal;color:#888;">(OAuth 2.0)</span></label>
		<input type="password" name="fs_client_secret" placeholder="Your Client Secret" required>
		<label>Consumer Secret <span style="font-weight:normal;color:#888;">(OAuth 1.0 REST API)</span></label>
		<div class="help">Found under "REST API OAuth 1.0 Credentials" on the developer portal</div>
		<input type="password" name="fs_consumer_secret" placeholder="Your Consumer Secret" required>
		<button type="submit" class="btn">Connect & Authorize</button>
	</form>
</div>
</body></html>`;
}

/** Render the connection choice page (shown after credential validation) */
export function renderConnectionChoice(params: {
	clientName?: string;
	error?: string;
	// OAuth 2.0 params to carry through
	clientId: string;
	redirectUri: string;
	state: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	scope: string;
}): string {
	const hiddenFields = `
		<input type="hidden" name="client_id" value="${escapeHtml(params.clientId)}">
		<input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
		<input type="hidden" name="state" value="${escapeHtml(params.state)}">
		<input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
		<input type="hidden" name="code_challenge_method" value="${escapeHtml(params.codeChallengeMethod)}">
		<input type="hidden" name="scope" value="${escapeHtml(params.scope)}">
	`;

	const errorHtml = params.error
		? `<div style="background:#fee;border:1px solid #fcc;padding:12px;border-radius:8px;margin-bottom:20px;color:#c33;">${escapeHtml(params.error)}</div>`
		: "";

	return `<!DOCTYPE html>
<html><head><title>Connect Your Account - FatSecret MCP</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
	body{font-family:system-ui,sans-serif;max-width:480px;margin:40px auto;padding:20px;background:#f5f5f5;}
	.card{background:white;border-radius:12px;padding:30px;box-shadow:0 2px 8px rgba(0,0,0,0.1);}
	h1{font-size:20px;margin:0 0 8px;}
	.subtitle{color:#666;font-size:14px;margin-bottom:20px;}
	.info-box{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:14px;margin-bottom:20px;font-size:13px;color:#1e40af;line-height:1.5;}
	.info-box strong{display:block;margin-bottom:4px;font-size:14px;}
	.option{border:2px solid #e5e7eb;border-radius:10px;padding:20px;margin-bottom:14px;transition:border-color 0.2s;}
	.option:hover{border-color:#22c55e;}
	.option h3{font-size:16px;margin:0 0 6px;color:#111;}
	.option p{font-size:13px;color:#666;margin:0 0 14px;line-height:1.5;}
	.option .tag{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;margin-bottom:8px;}
	.tag-recommended{background:#dcfce7;color:#166534;}
	.tag-basic{background:#f3f4f6;color:#6b7280;}
	.btn{width:100%;padding:12px;border:none;border-radius:8px;font-size:15px;cursor:pointer;font-weight:500;text-align:center;}
	.btn-primary{background:#22c55e;color:white;}
	.btn-primary:hover{background:#16a34a;}
	.btn-secondary{background:#f3f4f6;color:#374151;border:1px solid #d1d5db;}
	.btn-secondary:hover{background:#e5e7eb;}
</style></head><body>
<div class="card">
	<h1>Connect Your Account</h1>
	<p class="subtitle">API credentials verified. Now choose how to connect your data.</p>
	${errorHtml}
	<div class="info-box">
		<strong>API credentials and FatSecret account are different things</strong>
		Your API credentials (from the developer portal) let this app talk to FatSecret's servers.
		But to access <em>your personal data</em> (food diary, weight log, etc.), you also need to
		sign in with your <strong>fatsecret.com account</strong> &mdash; the one you use to log meals.
	</div>

	<div class="option">
		<span class="tag tag-recommended">Recommended</span>
		<h3>Sign in with your FatSecret account</h3>
		<p>Links your existing food diary, weight history, and saved meals. You'll be redirected to fatsecret.com to sign in.</p>
		<form method="POST" action="/oauth2/authorize">
			${hiddenFields}
			<input type="hidden" name="action" value="connect_account">
			<button type="submit" class="btn btn-primary">Sign in to FatSecret</button>
		</form>
	</div>

	<div class="option">
		<span class="tag tag-basic">Basic</span>
		<h3>Start with a blank profile</h3>
		<p>Creates a new empty profile. You can search foods and recipes, but you won't have any existing diary data. Good if you don't have a fatsecret.com account.</p>
		<form method="POST" action="/oauth2/authorize">
			${hiddenFields}
			<input type="hidden" name="action" value="create_profile">
			<button type="submit" class="btn btn-secondary">Create blank profile</button>
		</form>
	</div>
</div>
</body></html>`;
}
