/*
	OG Image Generator

	Basic usage
	https://your-site.com/og

	With custom title
	https://your-site.com/og?title=Custom%20Title

	With custom description
	https://your-site.com/og?description=Custom%20Description

	With light mode
	https://your-site.com/og?mode=light

	Full customization
	https://your-site.com/og?title=Custom%20Title&description=Custom%20Description&mode=dark
*/

import { siteConfig } from "@/config/site-config";
import { ImageResponse } from "next/og";
import type { NextRequest } from "next/server";

// Set to 'nodejs' runtime for better compatibility with bots
export const runtime = 'nodejs';

// Helper function for random number in a range
const random = (min: number, max: number) => Math.random() * (max - min) + min;

export async function GET(req: NextRequest) {
	try {
		const { searchParams } = new URL(req.url);
		const title = searchParams.get("title") ?? siteConfig.title;
		const mode = searchParams.get("mode") ?? "dark"; // Keep mode for subtle variations
		const description = searchParams.get("description") ?? siteConfig.description;

		// Create a cache key based on the input parameters
		const cacheKey = `${title}-${mode}-${description}`;

		const isDark = mode === "dark";

		// More vibrant and complex abstract gradient backgrounds
		const darkBg = {
			base: "#020617", // Very dark blue base
			gradient1: "radial-gradient(circle at 10% 20%, #7c3aed 0%, transparent 50%)", // Violet burst
			gradient2: "radial-gradient(circle at 90% 80%, #2563eb 0%, transparent 60%)", // Blue burst
			gradient3: "radial-gradient(circle at 50% 50%, #db2777 0%, transparent 70%)", // Pink burst (subtle)
		};
		const lightBg = {
			base: "#f0f9ff", // Very light blue base
			gradient1: "radial-gradient(circle at 15% 25%, #f97316 0%, transparent 50%)", // Orange burst
			gradient2: "radial-gradient(circle at 85% 75%, #0ea5e9 0%, transparent 60%)", // Sky blue burst
			gradient3: "radial-gradient(circle at 40% 60%, #d946ef 0%, transparent 70%)", // Fuchsia burst (subtle)
		};

		const currentBg = isDark ? darkBg : lightBg;

		// Define soft blurred shapes
		const shapes = Array.from({ length: 3 }).map((_, i) => ({
			x: random(0, 100),
			y: random(0, 100),
			size: random(400, 800),
			opacity: random(0.1, 0.3),
			color: isDark
				? ["#3b82f6", "#a855f7", "#ec4899"][i]
				: ["#fb923c", "#38bdf8", "#f472b6"][i],
		}));

		const textColor = isDark ? "#f8fafc" : "#0f172a"; // Adjusted for deeper contrast
		const descriptionColor = isDark ? "#cbd5e1" : "#334155"; // Adjusted

		// Log the request for debugging
		console.log(`Generating OG image: ${cacheKey}`);
		console.log(`User-Agent: ${req.headers.get('user-agent')}`);

		// --- Noise pattern definition (kept subtle) ---
		const noiseSize = '2px';
		const noiseColorDark = 'rgba(255, 255, 255, 0.015)';
		const noiseColorLight = 'rgba(0, 0, 0, 0.015)';
		const noiseColor = isDark ? noiseColorDark : noiseColorLight;
		const noiseGradient = `radial-gradient(${noiseColor} 1px, transparent 0)`;
		const noiseBackgroundImage = `${noiseGradient}, ${noiseGradient}`;
		const noiseBackgroundSize = `${noiseSize} ${noiseSize}, ${noiseSize} ${noiseSize}`;
		const noiseBackgroundPosition = `0 0, ${Number.parseInt(noiseSize) / 2}px ${Number.parseInt(noiseSize) / 2}px`;

		const response = new ImageResponse(
			<div // Outer container
				style={{
					height: "100%",
					width: "100%",
					display: "flex",
					position: "relative",
					flexDirection: "column",
					alignItems: "center",
					justifyContent: "center",
					backgroundColor: currentBg.base, // Base color
					fontFamily: '"Inter", sans-serif',
					overflow: "hidden", // Hide overflowing gradients/shapes
				}}
			>
				{/* Layered Background Gradients */}
				<div style={{ position: 'absolute', inset: 0, background: currentBg.gradient1, opacity: 0.6, filter: 'blur(100px)' }} />
				<div style={{ position: 'absolute', inset: 0, background: currentBg.gradient2, opacity: 0.5, filter: 'blur(120px)' }} />
				<div style={{ position: 'absolute', inset: 0, background: currentBg.gradient3, opacity: 0.4, filter: 'blur(150px)' }} />

				{/* Soft Blurred Shapes */}
				{shapes.map((shape, index) => (
					<div
						key={`shape-${index}`}
						style={{
							position: 'absolute',
							left: `${shape.x}%`,
							top: `${shape.y}%`,
							width: `${shape.size}px`,
							height: `${shape.size}px`,
							background: shape.color,
							opacity: shape.opacity,
							borderRadius: '50%',
							filter: 'blur(150px)', // Heavy blur
							transform: 'translate(-50%, -50%)', // Center the shapes
						}}
					/>
				))}

				{/* Noise Overlay */}
				<div
					style={{
						position: 'absolute',
						inset: 0,
						backgroundImage: noiseBackgroundImage,
						backgroundSize: noiseBackgroundSize,
						backgroundPosition: noiseBackgroundPosition,
						opacity: 0.8, // Slightly increased opacity for texture
						mixBlendMode: 'soft-light', // Different blend mode for subtlety
						zIndex: 1, // Ensure noise is above background but below content
					}}
				/>

				{/* Content Container (ensure it's above the noise and background effects) */}
				<div
					style={{
						display: "flex",
						flexDirection: "column",
						alignItems: "center",
						justifyContent: "center",
						gap: 32,
						maxWidth: "85%",
						textAlign: "center",
						zIndex: 2, // Content must be on top
						// Add a very subtle backdrop for text readability if needed
						// background: isDark ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)',
						// backdropFilter: 'blur(5px)',
						// padding: '20px',
						// borderRadius: '16px'
					}}
				>
					{/* Simplified Logo/Site Name */}
					<div
						style={{
							display: "flex",
							alignItems: "center",
							gap: 16,
							// Add slight shadow to lift logo/name off the busy background
							filter: 'drop-shadow(0 2px 5px rgba(0,0,0,0.2))'
						}}
					>
						{/* Optional: Replace with SVG logo */}
						<div
							style={{
								width: 64,
								height: 64,
								borderRadius: "16px",
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
								fontSize: 32,
								background: isDark ? "rgba(255, 255, 255, 0.1)" : "rgba(0, 0, 0, 0.05)",
								border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.15)' : 'rgba(0, 0, 0, 0.08)'}`,
								boxShadow: '0 4px 10px rgba(0,0,0,0.1)',
							}}
						>
							🚀
						</div>
						<div
							style={{
								fontSize: 36,
								fontWeight: 700,
								color: textColor,
							}}
						>
							{siteConfig.title}
						</div>
					</div>

					{/* Title and Description */}
					<div
						style={{
							display: "flex",
							flexDirection: "column",
							gap: 16,
						}}
					>
						<h1
							style={{
								fontSize: 68,
								fontWeight: 800,
								letterSpacing: "-0.04em",
								lineHeight: 1.2,
								margin: 0,
								padding: 0,
								color: textColor,
								textShadow: isDark ? '0 2px 8px rgba(0,0,0,0.5)' : '0 2px 8px rgba(0,0,0,0.15)',
							}}
						>
							{title}
						</h1>
						{description && (
							<p
								style={{
									fontSize: 30,
									color: descriptionColor,
									margin: 0,
									padding: 0,
									lineHeight: 1.5,
									maxWidth: "80%",
									textShadow: isDark ? '0 1px 4px rgba(0,0,0,0.4)' : '0 1px 4px rgba(0,0,0,0.1)',
								}}
							>
								{description}
							</p>
						)}
					</div>
				</div>
			</div>,
			{
				width: 1200,
				height: 630,
				// Ensure fonts are loaded if using custom fonts, especially weights 400, 700, 800
				// fonts: [ ... ]
				debug: false,
			}
		);

		// Add proper headers
		response.headers.set('Content-Type', 'image/png');
		response.headers.set('Cache-Control', 'public, immutable, no-transform, max-age=31536000');

		return response;
	} catch (e) {
		console.error('OG Image Generation Error:', e);

		// Return a simple fallback image with error details
		return new ImageResponse(
			<div
				style={{
					height: "100%",
					width: "100%",
					display: "flex",
					flexDirection: "column",
					alignItems: "center",
					justifyContent: "center",
					backgroundColor: "#000000",
					color: "#ffffff",
					padding: "40px",
					textAlign: "center",
				}}
			>
				<h1 style={{ fontSize: 60, marginBottom: 20 }}>{siteConfig.title}</h1>
				<p style={{ fontSize: 30 }}>Image generation failed</p>
				{/* Optionally include error message in dev */}
				{/* {process.env.NODE_ENV === 'development' && e instanceof Error && (
					<p style={{ fontSize: 20, color: '#ff6b6b', maxWidth: '80%' }}>{e.message}</p>
				)} */}
			</div>,
			{
				width: 1200,
				height: 630,
				status: 500,
				headers: {
					'Content-Type': 'image/png',
					'Cache-Control': 'no-cache, no-store',
				},
			}
		);
	}
}
