/**
 * Home page view
 */

export function renderHomePage(): string {
	return `<!DOCTYPE html>
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
</html>`;
}
