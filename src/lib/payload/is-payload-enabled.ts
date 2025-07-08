import { env } from "@/env";
import "server-only";

/**
 * Check if Payload CMS is enabled based on environment variables
 * @returns true if both DATABASE_URL and ENABLE_PAYLOAD are set
 */
export function isPayloadEnabled(): boolean {
	return !!(env.DATABASE_URL && env.ENABLE_PAYLOAD === "true");
}
