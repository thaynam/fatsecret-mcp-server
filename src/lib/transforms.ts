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
	const date = dateString ? new Date(dateString) : new Date();
	const epochStart = new Date("1970-01-01");
	const daysSinceEpoch = Math.floor(
		(date.getTime() - epochStart.getTime()) / (1000 * 60 * 60 * 24),
	);
	return daysSinceEpoch.toString();
}

/**
 * Convert FatSecret's "days since epoch" format back to YYYY-MM-DD
 *
 * @param daysSinceEpoch Number of days since 1970-01-01
 * @returns Date string in YYYY-MM-DD format
 */
export function fatSecretFormatToDate(daysSinceEpoch: number): string {
	const date = new Date(daysSinceEpoch * 24 * 60 * 60 * 1000);
	return date.toISOString().split("T")[0];
}

/**
 * Clean a value - converts null/undefined/empty string to undefined
 */
export function cleanValue<T>(value: T | null | undefined): T | undefined {
	if (value === null || value === undefined || value === "") {
		return undefined;
	}
	return value;
}

/**
 * Remove undefined values from an object
 */
export function removeUndefined<T extends Record<string, unknown>>(
	obj: T,
): Partial<T> {
	const result: Partial<T> = {};
	for (const [key, value] of Object.entries(obj)) {
		if (value !== undefined) {
			(result as any)[key] = value;
		}
	}
	return result;
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
 * Parse FatSecret API response - handles both JSON and querystring formats
 */
export function parseResponse(text: string): any {
	try {
		return JSON.parse(text);
	} catch {
		// FatSecret OAuth endpoints return query string format
		const params = new URLSearchParams(text);
		const result: Record<string, string> = {};
		for (const [key, value] of params) {
			result[key] = value;
		}
		return result;
	}
}
