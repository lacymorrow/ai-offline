import { defineConfig, devices } from "@playwright/test";
import path from "path";
import { fileURLToPath } from "url";

// Get the directory name in an ES module context
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Use process.env.PORT by default and fallback to 3000 if not available.
const PORT = process.env.PORT || 3000;
const baseURL = `http://localhost:${PORT}`;

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
	// Timeout per test
	timeout: 30 * 1000,
	// Test directory
	testDir: path.join(__dirname, "tests/e2e"),
	// If a test fails, retry it additional 2 times
	retries: 2,
	// Artifacts folder where screenshots, videos, and traces are stored.
	outputDir: "test-results/",

	// Run your local dev server before starting the tests:*
	// https://playwright.dev/docs/test-advanced#launching-a-development-web-server-during-the-tests
	webServer: {
		command: "pnpm dev",
		url: baseURL,
		timeout: 120 * 1000,
		reuseExistingServer: !process.env.CI,
	},

	use: {
		// Use baseURL so to make navigations relative.
		// More information: https://playwright.dev/docs/api/class-testoptions#test-options-base-url
		baseURL,

		// Retry a test if its failing with enabled tracing. This allows you to analyse the DOM, console logs, network traffic etc.
		// More information: https://playwright.dev/docs/trace-viewer
		trace: "retry-with-trace",

		// All available context options: https://playwright.dev/docs/api/class-browser#browser-new-context
		// contextOptions: {
		//   ignoreHTTPSErrors: true,
		// }
	},

	projects: [
		{
			name: "Desktop Chrome",
			use: {
				...devices["Desktop Chrome"],
			},
		},
		// {
		//   name: 'Desktop Firefox',
		//   use: {
		//     ...devices['Desktop Firefox'],
		//   },
		// },
		// {
		//   name: 'Desktop Safari',
		//   use: {
		//     ...devices['Desktop Safari'],
		//   },
		// },
		// Test against mobile viewports.
		// {
		//   name: 'Mobile Chrome',
		//   use: {
		//     ...devices['Pixel 5'],
		//   },
		// },
		// {
		//   name: 'Mobile Safari',
		//   use: devices['iPhone 12'],
		// },
	],
});
