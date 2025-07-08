import { detectSpam } from "@/app/(app)/ai/spam/spam-service";
import { validateApiKey } from "@/lib/api-key-validator";
import { rateLimiter } from "@/lib/rate-limit";
import { logRequest } from "@/lib/request-logger";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";

// Input validation schema
const requestSchema = z.object({
	text: z.string().min(1).max(10000),
	apiKey: z.string().min(1),
});

export async function POST(request: Request) {
	const startTime = Date.now();
	const headersList = await headers();
	const ip = headersList.get("x-forwarded-for") || "unknown";
	let statusCode = 200;

	try {
		// Check rate limit if enabled
		if (rateLimiter) {
			const { success } = await rateLimiter.limit(ip);
			if (!success) {
				statusCode = 429;
				return NextResponse.json({ error: "Too many requests" }, { status: statusCode });
			}
		}

		// Parse and validate request body
		const body = await request.json();
		const validatedData = requestSchema.safeParse(body);

		if (!validatedData.success) {
			statusCode = 400;
			return NextResponse.json(
				{
					error: "Invalid request data",
					details: validatedData.error.issues,
				},
				{ status: statusCode }
			);
		}

		// Validate API key
		const keyInfo = await validateApiKey(validatedData.data.apiKey);
		if (!keyInfo) {
			statusCode = 401;
			return NextResponse.json({ error: "Invalid API key" }, { status: statusCode });
		}

		// Detect spam
		const result = await detectSpam(validatedData.data.text);

		// Log request
		await logRequest({
			timestamp: new Date().toISOString(),
			ip,
			method: "POST",
			path: "/api/spam",
			statusCode,
			duration: Date.now() - startTime,
			apiKey: validatedData.data.apiKey,
		});

		// Return result
		return NextResponse.json(result);
	} catch (error) {
		console.error("Error in spam detection API:", error);
		statusCode = 500;

		// Log error request
		await logRequest({
			timestamp: new Date().toISOString(),
			ip,
			method: "POST",
			path: "/api/spam",
			statusCode,
			duration: Date.now() - startTime,
			apiKey: "error",
		});

		// Don't expose internal error details
		return NextResponse.json({ error: "Internal server error" }, { status: statusCode });
	}
}

// Return API documentation for GET requests
export async function GET() {
	return NextResponse.json({
		name: "Spam Detection API",
		version: "1.0.0",
		description: "API for detecting spam in text content",
		endpoints: {
			"/api/spam": {
				post: {
					description: "Detect spam in text content",
					requestBody: {
						required: true,
						content: {
							"application/json": {
								schema: {
									type: "object",
									required: ["text", "apiKey"],
									properties: {
										text: {
											type: "string",
											description: "The text to analyze",
											minLength: 1,
											maxLength: 10000,
										},
										apiKey: {
											type: "string",
											description: "Your API key",
										},
									},
								},
							},
						},
					},
					responses: {
						200: {
							description: "Successful response",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											label: {
												type: "string",
												enum: ["Spam", "Not Spam"],
											},
											score: {
												type: "number",
												description: "Confidence score between 0 and 1",
											},
											explanation: {
												type: "string",
												description: "Human-readable explanation of the result",
											},
										},
									},
								},
							},
						},
						400: {
							description: "Invalid request data",
						},
						401: {
							description: "Invalid API key",
						},
						429: {
							description: "Too many requests",
						},
						500: {
							description: "Internal server error",
						},
					},
				},
			},
		},
	});
}
