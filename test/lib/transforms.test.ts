/**
 * Transforms Tests
 *
 * Tests for data transformation utilities.
 */

import { describe, it, expect } from "vitest";
import {
	dateToFatSecretFormat,
	fatSecretFormatToDate,
	cleanValue,
	removeUndefined,
	normalizeMealType,
	parseResponse,
} from "../../src/lib/transforms.js";

describe("Date Transforms", () => {
	describe("dateToFatSecretFormat", () => {
		it("should convert a date to days since epoch", () => {
			// Jan 1, 1970 = day 0
			expect(dateToFatSecretFormat("1970-01-01")).toBe("0");

			// Jan 2, 1970 = day 1
			expect(dateToFatSecretFormat("1970-01-02")).toBe("1");
		});

		it("should handle recent dates", () => {
			// Jan 1, 2024 should be around 19724 days
			const result = parseInt(dateToFatSecretFormat("2024-01-01"), 10);
			expect(result).toBeGreaterThan(19000);
			expect(result).toBeLessThan(20000);
		});

		it("should use today's date when no date provided", () => {
			const result = parseInt(dateToFatSecretFormat(), 10);
			const expected = Math.floor(Date.now() / (1000 * 60 * 60 * 24));

			// Allow 1 day tolerance for timezone differences
			expect(Math.abs(result - expected)).toBeLessThanOrEqual(1);
		});
	});

	describe("fatSecretFormatToDate", () => {
		it("should convert days since epoch to YYYY-MM-DD", () => {
			expect(fatSecretFormatToDate(0)).toBe("1970-01-01");
			expect(fatSecretFormatToDate(1)).toBe("1970-01-02");
		});

		it("should round-trip with dateToFatSecretFormat", () => {
			const originalDate = "2024-06-15";
			const days = parseInt(dateToFatSecretFormat(originalDate), 10);
			const result = fatSecretFormatToDate(days);
			expect(result).toBe(originalDate);
		});
	});
});

describe("Data Cleaning", () => {
	describe("cleanValue", () => {
		it("should return undefined for null", () => {
			expect(cleanValue(null)).toBeUndefined();
		});

		it("should return undefined for undefined", () => {
			expect(cleanValue(undefined)).toBeUndefined();
		});

		it("should return undefined for empty string", () => {
			expect(cleanValue("")).toBeUndefined();
		});

		it("should return the value for non-empty values", () => {
			expect(cleanValue("test")).toBe("test");
			expect(cleanValue(0)).toBe(0);
			expect(cleanValue(false)).toBe(false);
		});
	});

	describe("removeUndefined", () => {
		it("should remove undefined values from object", () => {
			const obj = {
				a: "value",
				b: undefined,
				c: 123,
				d: undefined,
			};

			const result = removeUndefined(obj);

			expect(result).toEqual({
				a: "value",
				c: 123,
			});
		});

		it("should keep null and empty string values", () => {
			const obj = {
				a: null,
				b: "",
				c: 0,
			};

			const result = removeUndefined(obj);

			expect(result).toEqual({
				a: null,
				b: "",
				c: 0,
			});
		});
	});
});

describe("Meal Type Normalization", () => {
	describe("normalizeMealType", () => {
		it("should keep breakfast, lunch, dinner unchanged", () => {
			expect(normalizeMealType("breakfast")).toBe("breakfast");
			expect(normalizeMealType("lunch")).toBe("lunch");
			expect(normalizeMealType("dinner")).toBe("dinner");
		});

		it("should convert snack to other", () => {
			expect(normalizeMealType("snack")).toBe("other");
		});
	});
});

describe("Response Parsing", () => {
	describe("parseResponse", () => {
		it("should parse valid JSON", () => {
			const json = '{"foods": {"food": [{"food_id": "123"}]}}';
			const result = parseResponse(json);

			expect(result).toEqual({
				foods: {
					food: [{ food_id: "123" }],
				},
			});
		});

		it("should parse query string format (OAuth responses)", () => {
			const queryString = "oauth_token=abc123&oauth_token_secret=xyz789";
			const result = parseResponse(queryString);

			expect(result).toEqual({
				oauth_token: "abc123",
				oauth_token_secret: "xyz789",
			});
		});
	});
});
