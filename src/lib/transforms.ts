/**
 * Data transformation utilities for FatSecret API
 */

/**
 * Convert a date string (YYYY-MM-DD) or Date to FatSecret's "days since epoch" format
 * FatSecret uses days since Unix epoch (1970-01-01) for date parameters
 *
 * @param dateString Date in YYYY-MM-DD format, or undefined for today
 * @returns Number of days since 1970-01-01 as a string
 */
export function dateToFatSecretFormat(dateString?: string): string {
	const MS_PER_DAY = 1000 * 60 * 60 * 24;
	let utcMs: number;

	if (dateString) {
		// Parse as UTC to avoid timezone offset issues
		utcMs = new Date(`${dateString}T00:00:00Z`).getTime();
		if (Number.isNaN(utcMs)) {
			throw new Error(`Invalid date: ${dateString}`);
		}
	} else {
		// "Today" in UTC
		const now = new Date();
		utcMs = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
	}

	return Math.floor(utcMs / MS_PER_DAY).toString();
}

/**
 * Convert meal type string to FatSecret format
 * FatSecret expects: breakfast, lunch, dinner, other (for snack)
 */
export function normalizeMealType(
	mealType: "breakfast" | "lunch" | "dinner" | "snack",
): string {
	if (mealType === "snack") {
		return "other";
	}
	return mealType;
}

/**
 * Escape HTML special characters to prevent XSS
 */
export function escapeHtml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

/**
 * Extract the session token from the fatsecret_session cookie
 */
export function getSessionCookie(cookieHeader?: string): string | undefined {
	return cookieHeader?.match(/fatsecret_session=([^;]+)/)?.[1];
}

/**
 * Parse FatSecret API response - handles both JSON and querystring formats
 */
export function parseResponse(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		// FatSecret OAuth endpoints return query string format
		const params = new URLSearchParams(text);
		const result: Record<string, string> = {};
		for (const [key, value] of params) {
			result[key] = value;
		}
		const keys = Object.keys(result);
		if (keys.length === 0 || (keys.length === 1 && result[keys[0]] === "")) {
			return { raw: text.length > 500 ? text.substring(0, 500) : text };
		}
		return result;
	}
}
