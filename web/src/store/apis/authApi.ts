import { baseApi, setStoredCsrfToken, clearStoredAuth } from "../baseApi";

export interface User {
	id: string;
	username: string;
	name?: string;
	email?: string;
	role: string;
	org_id: string;
	created_at: string;
}

export interface Workspace {
	id: string;
	name: string;
	org_id: string;
	role: string;
}

export interface LoginRequest {
	username: string;
	password: string;
}

export interface LoginResponse {
	success: boolean;
	token?: string;
	user: User;
	expires_at?: string;
	csrf_token?: string;
}

export interface RegisterRequest {
	name?: string;
	username: string;
	email?: string;
	password: string;
	org_id?: string;
	role?: string;
}

export interface RegisterResponse {
	success: boolean;
	user: User;
	message: string;
}

export const authApi = baseApi.injectEndpoints({
	overrideExisting: false,
	endpoints: (builder) => ({
		login: builder.mutation<LoginResponse, LoginRequest>({
			query: (credentials) => ({
				url: "/api/v1/auth/login",
				method: "POST",
				body: credentials,
			}),
			onQueryStarted: async (_arg, { queryFulfilled }) => {
				try {
					const { data } = await queryFulfilled;
					// Session JWT is securely maintained exclusively in HttpOnly, Secure cookie
					// Store non-sensitive user metadata and CSRF token for Double-Submit protection
					if (data.user) {
						localStorage.setItem("platform_user", JSON.stringify(data.user));
					}
					if (data.csrf_token) {
						setStoredCsrfToken(data.csrf_token);
					}
				} catch {
					// Login failed
				}
			},
			invalidatesTags: ["Profile", "Workspaces", "Labs", "Grants"],
		}),

		register: builder.mutation<RegisterResponse, RegisterRequest>({
			query: (payload) => ({
				url: "/api/v1/auth/register",
				method: "POST",
				body: payload,
			}),
		}),

		logout: builder.mutation<{ success: boolean; message: string }, void>({
			query: () => ({
				url: "/api/v1/auth/logout",
				method: "POST",
			}),
			onQueryStarted: async (_arg, { queryFulfilled }) => {
				try {
					await queryFulfilled;
				} finally {
					clearStoredAuth();
				}
			},
			invalidatesTags: ["Profile", "Workspaces", "Labs", "Grants"],
		}),

		getProfile: builder.query<User, void>({
			query: () => "/api/v1/auth/me",
			onQueryStarted: async (_arg, { queryFulfilled }) => {
				try {
					const { data } = await queryFulfilled;
					if ((data as any)?.csrf_token) {
						setStoredCsrfToken((data as any).csrf_token);
					}
				} catch {
					// Ignored
				}
			},
			providesTags: ["Profile"],
		}),

		getWorkspaces: builder.query<Workspace[], void>({
			query: () => "/api/v1/workspaces",
			providesTags: ["Workspaces"],
		}),
	}),
});

export const {
	useLoginMutation,
	useRegisterMutation,
	useLogoutMutation,
	useGetProfileQuery,
	useGetWorkspacesQuery,
} = authApi;
