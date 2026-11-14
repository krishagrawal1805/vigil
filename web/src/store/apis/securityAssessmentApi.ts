import { baseApi, setStoredCsrfToken } from "../baseApi";

export interface CallerProfile {
	user_id: string;
	org_id: string;
	role: string;
	authenticated: boolean;
	csrf_token?: string;
}

export interface LabSession {
	lab_instance_id: string;
	container_id: string;
	target_host: string;
	target_port: number;
	target_url: string;
	browser_url?: string;
	browser_target_url?: string;
	grant_id: string;
	assessment_id: string;
	user_id: string;
	org_id: string;
	status: "starting" | "running" | "stopped" | "failed";
	created_at: string;
	expires_at: string;
}

export type ApprovalStatus =
	| "pending"
	| "dns_verified_pending_approval"
	| "approved"
	| "rejected"
	| "revoked"
	| "expired";

export interface AuthorizationGrant {
	grant_id: string;
	assessment_id: string;
	user_id: string;
	org_id: string;
	assessment_type: "managed_lab" | "external_assessment";
	lab_instance_id?: string;
	container_id?: string;
	authorized_host: string;
	authorized_port: number;
	resolved_target: string;
	allowed_cidrs: string[];
	allowed_ports: number[];
	allowed_paths: string[];
	blocked_paths: string[];
	allowed_methods: string[];
	start_time: string;
	expiry_time: string;
	dns_challenge_token?: string;
	dns_verified: boolean;
	dns_verified_at?: string;
	auth_evidence_ref?: string;
	approver_id?: string;
	approver_role?: string;
	approval_status: ApprovalStatus;
	approved_at?: string;
	is_revoked: boolean;
	revoked_at?: string;
	revocation_reason?: string;
	created_at: string;
	updated_at: string;
}

export interface StartLabResponse {
	lab_session: LabSession;
	grant: AuthorizationGrant;
}

export interface StopLabResponse {
	lab_instance_id: string;
	container_id: string;
	grant_id: string;
	status: string;
	message: string;
}

export interface RegisterExternalRequest {
	target_host: string;
	target_port?: number;
	allowed_cidrs?: string[];
	allowed_paths?: string[];
	blocked_paths?: string[];
	allowed_methods?: string[];
	auto_approve?: boolean;
}

export interface RegisterExternalResponse {
	grant: AuthorizationGrant;
	dns_challenge: {
		record_type: string;
		record_name: string;
		record_value: string;
		instructions: string;
	};
	note: string;
}

export interface VerifyDNSRequest {
	assessment_id: string;
	token: string;
}

export interface VerifyDNSResponse {
	assessment_id: string;
	status: string;
	dns_verified: boolean;
	grant: AuthorizationGrant;
	message: string;
}

export interface ApproveExternalRequest {
	assessment_id: string;
	auth_evidence_ref: string;
	duration?: number;
}

export interface SecurityFinding {
	id: string;
	title: string;
	severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
	category: string;
	cwe: string;
	affected_url: string;
	method?: string;
	parameter?: string;
	confidence: string;
	verification: string;
	evidence: string;
	negative_control?: string;
	counterevidence?: string;
	corroborated_tool_invocation?: string;
	validator_decision_id?: string;
	evidence_record_id?: string;
	recommendation: string;
	remediation_time: string;
	description?: string;
	hypothesis_id?: string;
	run_id?: string;
}

export interface BlockedScopeRequest {
	target_url: string;
	reason: string;
	timestamp: string;
}

export interface ToolExecution {
	tool: string;
	invocations: number;
	status: string;
}

export interface ToolInvocationRecord {
	invocation_id: string;
	task_id?: string;
	assessment_id?: string;
	run_id?: string;
	tool: string;
	target: string;
	method?: string;
	execution_status?: "SUCCESS" | "FAILED" | "BLOCKED" | "ERROR";
	security_outcome?: "CONFIRMED" | "RULED_OUT" | "INCONCLUSIVE" | "NOT_EVALUATED";
	is_error: boolean;
	confirmed: boolean;
	details?: string;
	timestamp: string;
}

export interface AssessmentResultsResponse {
	run_id?: string;
	assessment_id: string;
	target: string;
	grant_id: string;
	status: string;
	pid?: number;
	agent_model?: string;
	start_time: string;
	end_time: string;
	duration_seconds?: number;
	lifecycle_duration_seconds?: number;
	scope: {
		allowed_cidrs: string[];
		allowed_ports: number[];
		allowed_paths: string[];
		blocked_paths: string[];
		allowed_methods: string[];
	};
	tools_executed: ToolExecution[];
	discovered_endpoints?: string[];
	tool_invocations?: ToolInvocationRecord[];
	hypotheses?: any[];
	findings: SecurityFinding[];
	blocked_requests: BlockedScopeRequest[];
	final_report?: string;
	error_message?: string;
}

export interface AssessmentStatusResponse {
	status: string;
	run_id?: string;
	assessment_id?: string;
	target?: string;
	pid?: number;
	start_time?: string;
	duration_seconds?: number;
	findings_count?: number;
	tools_count?: number;
	invocations_count?: number;
	blocked_count?: number;
	agent_model?: string;
	error_message?: string;
	message?: string;
}

export interface StopAssessmentResponse {
	status: string;
	run_id: string;
	message: string;
}

export interface AuditEvent {
	id: string;
	timestamp: string;
	event_type: string;
	user_id: string;
	org_id: string;
	details: string;
}

export const securityAssessmentApi = baseApi.injectEndpoints({
	overrideExisting: false,
	endpoints: (builder) => ({
		// Profile
		getCallerProfile: builder.query<CallerProfile, void>({
			query: () => "/api/lab/me",
			onQueryStarted: async (_arg, { queryFulfilled }) => {
				try {
					const { data } = await queryFulfilled;
					if (data?.csrf_token) {
						setStoredCsrfToken(data.csrf_token);
					}
				} catch {
					// profile query failed
				}
			},
			providesTags: ["Profile"],
		}),

		// Practice Labs
		getManagedLabs: builder.query<LabSession[], void>({
			query: () => "/api/lab/list",
			providesTags: ["Labs"],
		}),

		getManagedLabStatus: builder.query<LabSession, string>({
			query: (instanceId) => `/api/lab/status?lab_instance_id=${encodeURIComponent(instanceId)}`,
		}),

		startManagedLab: builder.mutation<StartLabResponse, { duration_minutes?: number }>({
			query: (body) => ({
				url: "/api/lab/start",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Labs", "Grants", "Audit"],
		}),

		stopManagedLab: builder.mutation<StopLabResponse, { lab_instance_id: string }>({
			query: (body) => ({
				url: "/api/lab/stop",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Labs", "Grants", "Audit"],
		}),

		// External Assessments
		getExternalAssessments: builder.query<AuthorizationGrant[], void>({
			query: () => "/api/auth/external/list",
			providesTags: ["Grants"],
		}),

		getExternalAssessmentStatus: builder.query<AuthorizationGrant, string>({
			query: (assessmentId) => `/api/auth/external/status?assessment_id=${encodeURIComponent(assessmentId)}`,
		}),

		registerExternalAssessment: builder.mutation<RegisterExternalResponse, RegisterExternalRequest>({
			query: (body) => ({
				url: "/api/auth/external/register",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Grants", "Audit"],
		}),

		verifyExternalDNS: builder.mutation<VerifyDNSResponse, VerifyDNSRequest>({
			query: (body) => ({
				url: "/api/auth/external/verify-dns",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Grants", "Audit"],
		}),

		approveExternalAssessment: builder.mutation<AuthorizationGrant, ApproveExternalRequest>({
			query: (body) => ({
				url: "/api/auth/external/approve",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Grants", "Audit"],
		}),

		revokeGrant: builder.mutation<AuthorizationGrant, { grant_id: string; reason?: string }>({
			query: (body) => ({
				url: "/api/auth/external/revoke",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Grants", "Audit"],
		}),

		// Autonomous Assessment Runner
		getAssessmentResults: builder.query<AssessmentResultsResponse, string | void>({
			query: (runId) => (runId ? `/api/assessment/results?run_id=${encodeURIComponent(runId)}` : "/api/assessment/results"),
			providesTags: ["Results"],
		}),

		getAssessmentStatus: builder.query<AssessmentStatusResponse, void>({
			query: () => "/api/assessment/status",
			providesTags: ["Status"],
		}),

		startAssessmentRun: builder.mutation<AssessmentResultsResponse, { grant_id?: string; target_url?: string }>({
			query: (body) => ({
				url: "/api/assessment/run",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Results", "Status", "Audit"],
		}),

		stopAssessmentRun: builder.mutation<StopAssessmentResponse, { run_id?: string; reason?: string }>({
			query: (body) => ({
				url: "/api/assessment/stop",
				method: "POST",
				body,
			}),
			invalidatesTags: ["Status", "Audit"],
		}),

		// Audit Trail
		getLabAuditEvents: builder.query<AuditEvent[], void>({
			query: () => "/api/lab/audit",
			providesTags: ["Audit"],
		}),
	}),
});

export const {
	useGetCallerProfileQuery,
	useGetManagedLabsQuery,
	useGetManagedLabStatusQuery,
	useStartManagedLabMutation,
	useStopManagedLabMutation,
	useGetExternalAssessmentsQuery,
	useGetExternalAssessmentStatusQuery,
	useRegisterExternalAssessmentMutation,
	useVerifyExternalDNSMutation,
	useApproveExternalAssessmentMutation,
	useRevokeGrantMutation,
	useGetAssessmentResultsQuery,
	useGetAssessmentStatusQuery,
	useStartAssessmentRunMutation,
	useStopAssessmentRunMutation,
	useGetLabAuditEventsQuery,
} = securityAssessmentApi;

