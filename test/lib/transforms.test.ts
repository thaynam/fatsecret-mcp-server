/**
 * Transforms Tests
 *
 * Tests for data transformation utilities.
 */

import { describe, it, expect } from "vitest";
import {
	dateToFatSecretFormat,
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
			const result = Number.parseInt(dateToFatSecretFormat("2024-01-01"), 10);
			expect(result).toBeGreaterThan(19000);
			expect(result).toBeLessThan(20000);
		});

		it("should use today's date when no date provided", () => {
			const result = Number.parseInt(dateToFatSecretFormat(), 10);
			const expected = Math.floor(Date.now() / (1000 * 60 * 60 * 24));

			// Allow 1 day tolerance for timezone differences
			expect(Math.abs(result - expected)).toBeLessThanOrEqual(1);
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
