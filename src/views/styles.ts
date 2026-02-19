/**
 * Shared styles and HTML shell for view templates
 */

export function baseStyles(): string {
	return `
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			   line-height: 1.6; color: #333; min-height: 100vh; padding: 20px;
			   background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
			   display: flex; align-items: center; justify-content: center; }
		.container { background: white; border-radius: 12px;
					 box-shadow: 0 20px 60px rgba(0,0,0,0.3);
					 max-width: 600px; width: 100%; padding: 40px; }
		.btn { padding: 12px 24px; border: none; border-radius: 8px;
			   font-size: 15px; font-weight: 600; cursor: pointer;
			   text-decoration: none; text-align: center; display: inline-block; }
		.btn-primary { background: #22c55e; color: white; }
		.btn-primary:hover { background: #16a34a; }
		.copy-btn { background: #4b5563; color: white; border: none;
					padding: 6px 12px; border-radius: 4px; cursor: pointer;
					font-size: 12px; margin-top: 10px; }
		.token-display { background: #f4f4f4; padding: 15px; border-radius: 5px;
						 font-family: monospace; font-size: 12px; word-break: break-all; }
		.config-example { background: #1e293b; color: #e2e8f0; padding: 15px;
						  border-radius: 8px; font-family: monospace; font-size: 13px;
						  overflow-x: auto; white-space: pre; }
	`;
}

export function pageShell(title: string, bodyHtml: string, extraStyles = ""): string {
	return `<!DOCTYPE html>
<html lang="en"><head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>${title}</title>
	<style>${baseStyles()}${extraStyles}</style>
</head><body>${bodyHtml}</body></html>`;
}
