import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";
import ts from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const eslintConfig = [
	// Base config for all files
	{
		languageOptions: {
			parserOptions: {
				project: ["./tsconfig.json"],
				tsconfigRootDir: __dirname,
			},
		},
		linterOptions: {
			reportUnusedDisableDirectives: true,
		},
	},

	// Configure global ignores (replaces .eslintignore)
	{
		ignores: [
			"node_modules/**",
			".cursor/**",
			".next/**",
			"src/app/(demo)/**/*",
			"src/components/blocks/**",
			"src/components/ui/**",
		],
	},

	/*
	 * eslint-config-next 16 ships flat configs as its own exports, so the
	 * eslintrc FlatCompat bridge this file used on 15.x is gone. Extending the
	 * legacy `next/core-web-vitals` name through FlatCompat against the 16
	 * package throws "Converting circular structure to JSON" out of the
	 * eslintrc config validator (LAC-6482).
	 */
	...nextCoreWebVitals,
	...nextTypescript,

	/*
	 * The same two rule sets the
	 * `plugin:@typescript-eslint/{recommended,stylistic}-type-checked`
	 * extends provided, spread as rules only. Those eslintrc configs also
	 * pull in typescript-eslint's `base`, which registers the
	 * `@typescript-eslint` plugin a second time, and flat config rejects that
	 * ("Cannot redefine plugin") now that eslint-config-next 16 registers it
	 * first.
	 */
	{
		files: ["**/*.{ts,tsx}"],
		rules: {
			...ts.configs["recommended-type-checked"].rules,
			...ts.configs["stylistic-type-checked"].rules,
		},
	},

	// TypeScript files configuration
	{
		files: ["**/*.{ts,tsx}"],
		languageOptions: {
			parser: tsParser,
			parserOptions: {
				project: ["./tsconfig.json"],
				tsconfigRootDir: __dirname,
				ecmaVersion: "latest",
				sourceType: "module",
				ecmaFeatures: {
					jsx: true,
				},
			},
		},
		/*
		 * No `plugins: { "@typescript-eslint": ts }` here: eslint-config-next
		 * 16's flat `typescript` config already registers that plugin, and
		 * flat config refuses to let a second block redefine it.
		 */
		rules: {
			...ts.configs.recommended.rules,
			"@typescript-eslint/no-unused-vars": [
				"warn",
				{
					argsIgnorePattern: "^_",
					varsIgnorePattern: "^_",
				},
			],
			"@typescript-eslint/consistent-type-imports": [
				"warn",
				{
					prefer: "type-imports",
					fixStyle: "inline-type-imports",
				},
			],
			// ! Todo: Enable
			"@typescript-eslint/ban-ts-comment": "warn",
			"@typescript-eslint/no-explicit-any": "warn",
			"@typescript-eslint/no-floating-promises": "warn",
			"@typescript-eslint/no-misused-promises": "warn",
			"@typescript-eslint/no-unsafe-argument": "warn",
			"@typescript-eslint/no-unsafe-assignment": "warn",
			"@typescript-eslint/no-unsafe-call": "warn",
			"@typescript-eslint/no-unsafe-member-access": "warn",
			"@typescript-eslint/no-unsafe-return": "warn",
		},
	},
];

export default eslintConfig;
