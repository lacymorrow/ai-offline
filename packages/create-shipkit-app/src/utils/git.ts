import { execa } from "execa";
import fs from "fs-extra";
import path from "path";

/**
 * Initialize a git repository and create initial commit
 */
export async function initializeGit(projectPath: string): Promise<void> {
	try {
		// Check if git is available
		await execa("git", ["--version"], { stdio: "ignore" });
	} catch {
		throw new Error("Git is not installed or not available in PATH");
	}

	try {
		// Initialize git repository
		await execa("git", ["init"], {
			cwd: projectPath,
			stdio: "ignore",
		});

		// Create .gitignore if it doesn't exist
		const gitignorePath = path.join(projectPath, ".gitignore");
		const gitignoreExists = await fs.pathExists(gitignorePath);

		if (!gitignoreExists) {
			const gitignoreContent = `# Dependencies
node_modules/
.pnp
.pnp.js

# Testing
/coverage

# Next.js
/.next/
/out/

# Production
/build

# Misc
.DS_Store
*.pem

# Debug
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Local env files
.env.local
.env.development.local
.env.test.local
.env.production.local

# Vercel
.vercel

# TypeScript
*.tsbuildinfo
next-env.d.ts

# IDE
.vscode/
.idea/

# OS
Thumbs.db
`;
			await fs.writeFile(gitignorePath, gitignoreContent);
		}

		// Stage all files
		await execa("git", ["add", "."], {
			cwd: projectPath,
			stdio: "ignore",
		});

		// Create initial commit
		await execa("git", ["commit", "-m", "Initial commit from create-shipkit-app"], {
			cwd: projectPath,
			stdio: "ignore",
		});
	} catch (error) {
		throw new Error(
			`Failed to initialize git repository: ${
				error instanceof Error ? error.message : "Unknown error"
			}`
		);
	}
}

/**
 * Check if git is available
 */
export async function checkGitAvailable(): Promise<boolean> {
	try {
		await execa("git", ["--version"], { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

/**
 * Check if current directory is already a git repository
 */
export async function isGitRepository(projectPath: string): Promise<boolean> {
	try {
		await execa("git", ["rev-parse", "--git-dir"], {
			cwd: projectPath,
			stdio: "ignore",
		});
		return true;
	} catch {
		return false;
	}
}
