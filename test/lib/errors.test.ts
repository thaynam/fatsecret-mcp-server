import { describe, it, expect } from "vitest";
import { handleError, successResponse, FatSecretApiError } from "../../src/lib/errors.js";
import { z } from "zod";

describe("successResponse", () => {
	it("should format a summary and data into MCP response", () => {
		const result = successResponse("Found 5 items", { count: 5 });
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toBe("Found 5 items");
		expect(result.content[1].text).toBe(JSON.stringify({ count: 5 }, null, 2));
	});

	it("should not include isError", () => {
		const result = successResponse("OK", {});
		expect(result.isError).toBeUndefined();
	});
});

describe("handleError", () => {
	it("should format FatSecretApiError", () => {
		const error = new FatSecretApiError("API failed", 400);
		const result = handleError(error);
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain("Invalid request parameters");
	});

	it("should format ZodError", () => {
		const schema = z.object({ name: z.string() });
		try {
			schema.parse({ name: 123 });
		} catch (error) {
			const result = handleError(error);
			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain("Validation");
		}
	});

	it("should format generic Error", () => {
		const result = handleError(new Error("something broke"));
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain("something broke");
	});

	it("should handle unknown error types", () => {
		const result = handleError("just a string");
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain("unknown error");
	});
});
