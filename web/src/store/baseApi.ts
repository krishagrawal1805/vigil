import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";

/**
 * Security Architecture:
 * - Session authentication relies strictly on HttpOnly, Secure, SameSite=Lax cookies.
 * - The session JWT is NOT stored in localStorage to protect against XSS token exfiltration.
 * - CSRF Double-Submit protection uses a client-readable csrf_token cookie submitted
 *   as the X-CSRF-Token header on mutating requests.
 */

// Legacy helper retained as null stub for type compatibility; JWT is never in localStorage
export const getStoredToken = (): string | null => null;
export const setStoredToken = (_token: string | null) => {
	// No-op: Session authentication is stored strictly in server-managed HttpOnly cookies
	if (typeof window !== "undefined") {
		localStorage.removeItem("platform_token");
	}
};

export const getCsrfToken = (): string | null => {
	if (typeof document !== "undefined" && document.cookie) {
		const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
		if (match && match[1]) {
			return decodeURIComponent(match[1].trim());
		}
	}
	if (typeof window !== "undefined") {
		return localStorage.getItem("platform_csrf_token");
	}
	return null;
};

export const setStoredCsrfToken = (token: string | null) => {
	if (typeof window === "undefined") return;
	if (token) {
		localStorage.setItem("platform_csrf_token", token);
	} else {
		localStorage.removeItem("platform_csrf_token");
	}
};

export const clearStoredAuth = () => {
	if (typeof window === "undefined") return;
	localStorage.removeItem("platform_token");
	localStorage.removeItem("platform_user");
	localStorage.removeItem("platform_active_workspace");
	localStorage.removeItem("platform_csrf_token");
};

export const baseApi = createApi({
	reducerPath: "baseApi",
	baseQuery: fetchBaseQuery({
		baseUrl: "", // Proxied to backend via Vite /api
		credentials: "include", // Send HttpOnly cookie automatically with every request
		prepareHeaders: (headers) => {
			if (!headers.has("Content-Type")) {
				headers.set("Content-Type", "application/json");
			}
			// Submit Double-Submit CSRF token header
			const csrf = getCsrfToken();
			if (csrf) {
				headers.set("X-CSRF-Token", csrf);
			}
			return headers;
		},
	}),
	tagTypes: ["Profile", "Labs", "Grants", "Results", "Status", "Audit", "Workspaces"],
	endpoints: () => ({}),
});
