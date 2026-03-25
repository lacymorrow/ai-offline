export interface CreateAppOptions {
	projectName?: string;
	template: string;
	features: string[];
	packageManager: "npm" | "pnpm" | "yarn";
	skipInstall: boolean;
	skipGit: boolean;
	useDefaults: boolean;
	verbose: boolean;
}

export interface ValidationResult {
	isValid: boolean;
	message?: string;
}

export interface FeatureConfig {
	name: string;
	description: string;
	dependencies: string[];
	devDependencies?: string[];
	envVars: string[];
	files?: string[];
	category: FeatureCategory;
}

export type FeatureCategory =
	| "authentication"
	| "database"
	| "email"
	| "payments"
	| "cms"
	| "analytics"
	| "deployment"
	| "ui";

export interface Template {
	name: string;
	description: string;
	features: string[];
	dependencies: string[];
	devDependencies?: string[];
}

export interface ProjectConfig {
	name: string;
	template: Template;
	selectedFeatures: FeatureConfig[];
	packageManager: CreateAppOptions["packageManager"];
	envVars: Record<string, string>;
}
