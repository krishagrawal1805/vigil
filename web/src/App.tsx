import React, { useState, useEffect } from "react";
import {
	useGetProfileQuery,
	useGetManagedLabsQuery,
	useStartManagedLabMutation,
	useStopManagedLabMutation,
	useGetExternalAssessmentsQuery,
	useRegisterExternalAssessmentMutation,
	useVerifyExternalDNSMutation,
	useApproveExternalAssessmentMutation,
	useRevokeGrantMutation,
	useGetAssessmentResultsQuery,
	useGetAssessmentStatusQuery,
	useStartAssessmentRunMutation,
	useStopAssessmentRunMutation,
	useGetLabAuditEventsQuery,
	RegisterExternalRequest,
} from "@/store";
import { AppHeader } from "@/components/layout/AppHeader";
import { Sidebar, ViewName } from "@/components/layout/Sidebar";
import { LoginPage } from "@/components/auth/LoginPage";
import { RegisterPage } from "@/components/auth/RegisterPage";
import { PublicLandingPage } from "@/components/views/PublicLandingPage";
import { WelcomeOnboardingView } from "@/components/views/WelcomeOnboardingView";
import { DashboardView } from "@/components/views/DashboardView";
import { AssessmentWizardView } from "@/components/views/AssessmentWizardView";
import { ExternalAssessmentWorkflowView } from "@/components/views/ExternalAssessmentWorkflowView";
import { LiveAssessmentView } from "@/components/views/LiveAssessmentView";
import { AttackPathView } from "@/components/views/AttackPathView";
import { FindingsView } from "@/components/views/FindingsView";
import { PracticeLabSection } from "@/components/sections/PracticeLabSection";
import { ExternalTargetsSection } from "@/components/sections/ExternalTargetsSection";
import { AuditTrailSection } from "@/components/sections/AuditTrailSection";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle2, RotateCcw } from "lucide-react";

export function App() {
	const [unauthMode, setUnauthMode] = useState<"landing" | "login" | "register">("landing");
	const [activeView, setActiveView] = useState<ViewName>(() => {
		if (typeof window !== "undefined") {
			const saved = sessionStorage.getItem("vigil_active_view");
			if (saved) return saved as ViewName;
		}
		return "welcome";
	});
	const [findingsSubTab, setFindingsSubTab] = useState<"overview" | "issues" | "findings" | "urls" | "coverage" | "activity" | "traffic" | "scope" | "report">(() => {
		if (typeof window !== "undefined") {
			const saved = sessionStorage.getItem("vigil_findings_tab");
			if (saved) return saved as any;
		}
		return "overview";
	});
	const [labDuration, setLabDuration] = useState<number>(60);
	const [copiedTarget, setCopiedTarget] = useState<boolean>(false);
	const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
	const [isStartingPractice, setIsStartingPractice] = useState<boolean>(false);

	// External Assessment Form State with Session Persistence
	const [extHost, setExtHostState] = useState<string>(() => (typeof window !== "undefined" ? sessionStorage.getItem("vigil_ext_host") || "" : ""));
	const [extPort, setExtPortState] = useState<number>(() => (typeof window !== "undefined" ? parseInt(sessionStorage.getItem("vigil_ext_port") || "443", 10) : 443));
	const [extAllowedPaths, setExtAllowedPathsState] = useState<string>(() => (typeof window !== "undefined" ? sessionStorage.getItem("vigil_ext_paths") || "" : ""));
	const [extBlockedPaths, setExtBlockedPathsState] = useState<string>(() => (typeof window !== "undefined" ? sessionStorage.getItem("vigil_ext_blocked") || "" : ""));

	const setExtHost = (val: string) => {
		setExtHostState(val);
		if (typeof window !== "undefined") sessionStorage.setItem("vigil_ext_host", val);
	};
	const setExtPort = (val: number) => {
		setExtPortState(val);
		if (typeof window !== "undefined") sessionStorage.setItem("vigil_ext_port", String(val));
	};
	const setExtAllowedPaths = (val: string) => {
		setExtAllowedPathsState(val);
		if (typeof window !== "undefined") sessionStorage.setItem("vigil_ext_paths", val);
	};
	const setExtBlockedPaths = (val: string) => {
		setExtBlockedPathsState(val);
		if (typeof window !== "undefined") sessionStorage.setItem("vigil_ext_blocked", val);
	};

	const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>("");
	const [dnsTokenInput, setDnsTokenInput] = useState<string>("");
	const [evidenceRef, setEvidenceRef] = useState<string>("");

	// User & Profile
	const {
		data: profile,
		isLoading: isProfileLoading,
		isError: isProfileError,
		refetch: refetchProfile,
	} = useGetProfileQuery();

	// Managed Labs
	const {
		data: managedLabs,
		isLoading: isLabsLoading,
		refetch: refetchLabs,
	} = useGetManagedLabsQuery(undefined, {
		pollingInterval: 5000,
		skip: !profile,
	});

	// External Grants
	const {
		data: externalGrants,
		isLoading: isGrantsLoading,
		refetch: refetchGrants,
	} = useGetExternalAssessmentsQuery(undefined, {
		pollingInterval: 6000,
		skip: !profile,
	});

	// Pentest Results & Live Status
	const {
		data: liveStatus,
		refetch: refetchStatus,
	} = useGetAssessmentStatusQuery(undefined, {
		pollingInterval: 2500,
		skip: !profile,
	});

	const {
		data: assessmentResults,
		refetch: refetchResults,
	} = useGetAssessmentResultsQuery(liveStatus?.run_id || undefined, {
		pollingInterval: 3000,
		skip: !profile,
	});

	// Audit Trail
	const {
		data: auditEvents,
		isLoading: isAuditLoading,
		refetch: refetchAudit,
	} = useGetLabAuditEventsQuery(undefined, {
		pollingInterval: 8000,
		skip: !profile,
	});

	// Mutations
	const [startLab, { isLoading: isStartingLab }] = useStartManagedLabMutation();
	const [stopLab, { isLoading: isStoppingLab }] = useStopManagedLabMutation();
	const [registerExternal, { isLoading: isRegisteringExt }] = useRegisterExternalAssessmentMutation();
	const [verifyDNS, { isLoading: isVerifyingDNS }] = useVerifyExternalDNSMutation();
	const [approveExternal, { isLoading: isApprovingExt }] = useApproveExternalAssessmentMutation();
	const [revokeGrant, { isLoading: isRevokingGrant }] = useRevokeGrantMutation();
	const [startAssessmentRun, { isLoading: isStartingRun }] = useStartAssessmentRunMutation();
	const [stopAssessmentRun, { isLoading: isStoppingRun }] = useStopAssessmentRunMutation();

	const handleRefreshAll = () => {
		refetchProfile();
		refetchLabs();
		refetchGrants();
		refetchResults();
		refetchStatus();
		refetchAudit();
	};

	const handleNavigate = (view: ViewName | string, subTab?: string, pushHistory: boolean = true) => {
		const v = view as ViewName;
		setActiveView(v);
		if (typeof window !== "undefined") {
			sessionStorage.setItem("vigil_active_view", v);
		}
		if (subTab) {
			setFindingsSubTab(subTab as any);
			if (typeof window !== "undefined") {
				sessionStorage.setItem("vigil_findings_tab", subTab);
			}
		}
		if (pushHistory && typeof window !== "undefined") {
			window.history.pushState({ view: v, subTab }, "", "");
		}
		setActionMessage(null);
	};

	// Restore view when user hits browser Back or Forward button
	useEffect(() => {
		const handlePopState = (e: PopStateEvent) => {
			if (e.state && e.state.view) {
				handleNavigate(e.state.view, e.state.subTab, false);
			} else if (typeof window !== "undefined") {
				const saved = sessionStorage.getItem("vigil_active_view");
				if (saved) {
					handleNavigate(saved, sessionStorage.getItem("vigil_findings_tab") || undefined, false);
				}
			}
		};
		window.addEventListener("popstate", handlePopState);
		return () => window.removeEventListener("popstate", handlePopState);
	}, []);

	const handleDirectPracticeLaunch = async () => {
		setActionMessage(null);
		setIsStartingPractice(true);
		try {
			// 1. Ensure lab session is active
			let activeLab = managedLabs?.find((l) => l.status === "running");
			let grantId = activeLab?.grant_id;
			if (!activeLab) {
				const labRes = await startLab({ duration_minutes: 60 }).unwrap();
				activeLab = labRes.lab_session;
				grantId = labRes.grant?.grant_id || labRes.lab_session?.grant_id || (labRes as any).grant_id;
			}
			// 2. Launch autonomous assessment immediately
			const res = await startAssessmentRun({ grant_id: grantId }).unwrap();
			setActionMessage({
				type: "success",
				text: `Autonomous Practice Lab assessment launched! Run ID: ${res.run_id || "active"}. Target: ${res.target}.`,
			});
			// 3. Directly navigate to Live Assessment view
			setActiveView("live-assessment");
			handleRefreshAll();
		} catch (err: any) {
			// If already running or launched, navigate to live-assessment
			setActiveView("live-assessment");
			handleRefreshAll();
		} finally {
			setIsStartingPractice(false);
		}
	};

	const handleSkipOnboarding = () => {
		localStorage.setItem("VIGIL_onboarding_completed", "true");
		setActiveView("dashboard");
	};

	const handleCopy = (text: string) => {
		navigator.clipboard.writeText(text);
		setCopiedTarget(true);
		setTimeout(() => setCopiedTarget(false), 2000);
	};

	const handleStartLab = async () => {
		setActionMessage(null);
		try {
			const res = await startLab({ duration_minutes: labDuration }).unwrap();
			setActionMessage({
				type: "success",
				text: `Managed lab ${res.lab_session.lab_instance_id} started at ${res.lab_session.browser_url || res.lab_session.browser_target_url || "http://127.0.0.1:5000"}. Internal agent binding: ${res.lab_session.target_url}.`,
			});
			handleRefreshAll();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "Failed to start practice lab target.",
			});
		}
	};

	const handleStopLab = async (labId: string) => {
		setActionMessage(null);
		try {
			await stopLab({ lab_instance_id: labId }).unwrap();
			setActionMessage({
				type: "success",
				text: `Practice lab ${labId} stopped and grant revoked.`,
			});
			handleRefreshAll();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "Failed to stop lab.",
			});
		}
	};

	const handleRegisterExternal = async (payload?: RegisterExternalRequest) => {
		setActionMessage(null);
		try {
			const reqPayload: RegisterExternalRequest = payload || {
				target_host: extHost,
				target_port: extPort,
				allowed_paths: extAllowedPaths.split(",").map((s) => s.trim()).filter(Boolean),
				blocked_paths: extBlockedPaths.split(",").map((s) => s.trim()).filter(Boolean),
				auto_approve: true,
			};
			const res = await registerExternal(reqPayload).unwrap();
			setSelectedAssessmentId(res.grant.assessment_id);
			setActionMessage({
				type: "success",
				text: `Target registered & authorized: ${res.grant.authorized_host}:${res.grant.authorized_port}. Ready for assessment.`,
			});
			handleRefreshAll();
			return res;
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "Failed to register target.",
			});
			throw err;
		}
	};

	const handleVerifyDNS = async () => {
		setActionMessage(null);
		if (!selectedAssessmentId) {
			setActionMessage({ type: "error", text: "Select an assessment ID first." });
			return;
		}
		try {
			const res = await verifyDNS({ assessment_id: selectedAssessmentId, token: dnsTokenInput }).unwrap();
			setActionMessage({
				type: "success",
				text: `DNS verification status: ${res.status}. Ownership cryptographically confirmed!`,
			});
			handleRefreshAll();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "DNS verification failed.",
			});
		}
	};

	const handleApproveExternal = async () => {
		setActionMessage(null);
		if (!selectedAssessmentId) {
			setActionMessage({ type: "error", text: "Select an assessment ID first." });
			return;
		}
		try {
			const res = await approveExternal({ assessment_id: selectedAssessmentId, auth_evidence_ref: evidenceRef }).unwrap();
			setActionMessage({
				type: "success",
				text: `Grant approved for target ${res.authorized_host}:${res.authorized_port}. ScopeEnforcer rule active.`,
			});
			handleRefreshAll();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "Failed to approve external grant.",
			});
		}
	};

	const handleRevokeGrant = async (grantId: string) => {
		setActionMessage(null);
		try {
			await revokeGrant({ grant_id: grantId, reason: "Operator manual revocation" }).unwrap();
			setActionMessage({
				type: "success",
				text: `Authorization grant ${grantId} revoked. Immediate network isolation applied.`,
			});
			handleRefreshAll();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "Failed to revoke grant.",
			});
		}
	};

	const handleStartAssessment = async (grantId?: string, targetUrl?: string) => {
		setActionMessage(null);
		try {
			let effectiveGrantId = grantId;
			if (!effectiveGrantId) {
				const activeLab = managedLabs?.find((l) => l.status === "running");
				if (activeLab?.grant_id) {
					effectiveGrantId = activeLab.grant_id;
				} else {
					return await handleDirectPracticeLaunch();
				}
			}
			const res = await startAssessmentRun({ grant_id: effectiveGrantId, target_url: targetUrl }).unwrap();
			setActionMessage({
				type: "success",
				text: `Autonomous pentest launched! Run ID: ${res.run_id || "active"}. Target: ${res.target}.`,
			});
			setActiveView("live-assessment");
			handleRefreshAll();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "Failed to start assessment run.",
			});
		}
	};

	const handleStopAssessment = async (runId?: string) => {
		setActionMessage(null);
		try {
			await stopAssessmentRun({ run_id: runId, reason: "Operator cancelled run" }).unwrap();
			setActionMessage({
				type: "success",
				text: "Assessment run stopped by operator.",
			});
			handleRefreshAll();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error || err?.message || "Failed to stop assessment run.",
			});
		}
	};

	const renderStatusBadge = (status: string) => {
		switch (status?.toLowerCase()) {
			case "running":
			case "active":
			case "starting":
				return <Badge className="bg-emerald-600/30 text-emerald-400 border border-emerald-500/40 text-[10px]">ACTIVE / RUNNING</Badge>;
			case "stopped":
				return <Badge variant="secondary" className="text-[10px]">STOPPED</Badge>;
			case "approved":
				return <Badge className="bg-emerald-600/30 text-emerald-400 border border-emerald-500/40 text-[10px]">APPROVED</Badge>;
			case "pending":
				return <Badge className="bg-amber-500/30 text-amber-300 border border-amber-500/40 text-[10px]">PENDING DNS</Badge>;
			case "dns_verified_pending_approval":
				return <Badge className="bg-blue-600/30 text-blue-300 border border-blue-500/40 text-[10px]">DNS VERIFIED</Badge>;
			case "revoked":
				return <Badge className="bg-rose-600/30 text-rose-300 border border-rose-500/40 text-[10px]">REVOKED</Badge>;
			default:
				return <Badge variant="outline" className="text-[10px]">{status}</Badge>;
		}
	};

	// Auth gate
	if (isProfileLoading) {
		return (
			<div className="flex min-h-screen items-center justify-center bg-background">
				<div className="flex flex-col items-center gap-3">
					<RotateCcw className="h-8 w-8 text-primary animate-spin" />
					<p className="text-xs font-mono text-muted-foreground">Initializing VIGIL Secure Workspace...</p>
				</div>
			</div>
		);
	}

	if (isProfileError || !profile) {
		if (unauthMode === "landing") {
			return (
				<PublicLandingPage
					onGetStarted={() => setUnauthMode("login")}
					onSignIn={() => setUnauthMode("login")}
				/>
			);
		}
		if (unauthMode === "login") {
			return (
				<LoginPage
					onSuccess={() => refetchProfile()}
					onSwitchToRegister={() => setUnauthMode("register")}
					onBackToWebsite={() => setUnauthMode("landing")}
				/>
			);
		}
		return (
			<RegisterPage
				onSuccess={() => setUnauthMode("login")}
				onSwitchToLogin={() => setUnauthMode("login")}
				onBackToWebsite={() => setUnauthMode("landing")}
			/>
		);
	}

	const isAssessmentRunning =
		liveStatus?.status === "running" ||
		liveStatus?.status === "starting" ||
		liveStatus?.status === "active";

	return (
		<div className="min-h-screen bg-background flex flex-col text-foreground">
			{/* Top Enterprise Header with Integrated Navigation */}
			<AppHeader
				onRefreshAll={handleRefreshAll}
				onLogout={() => {
					refetchProfile();
				}}
				activeView={activeView}
				onNavigate={handleNavigate}
				findingsCount={assessmentResults?.findings?.length || 0}
			/>

			{/* Main Layout: Full-Width Clean Viewport without Distracting Sidebar */}
			<div className="flex-1 flex overflow-hidden">
				{/* Main Viewport Content Area */}
				<main className={`flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-6 ${activeView === "welcome" ? "max-w-5xl mx-auto w-full py-8" : "max-w-7xl mx-auto w-full"}`}>
					{/* Notification Banner */}
					{actionMessage && (
						<Alert variant={actionMessage.type === "error" ? "destructive" : "default"} className="py-2.5">
							{actionMessage.type === "error" ? (
								<AlertTriangle className="h-4 w-4" />
							) : (
								<CheckCircle2 className="h-4 w-4 text-emerald-400" />
							)}
							<AlertTitle className="text-xs font-semibold">
								{actionMessage.type === "error" ? "Security Action Blocked" : "Action Success"}
							</AlertTitle>
							<AlertDescription className="text-xs">{actionMessage.text}</AlertDescription>
						</Alert>
					)}

					{/* View 0: Welcome Category Selection Screen (No sidebar, clean single screen) */}
					{activeView === "welcome" && (
						<WelcomeOnboardingView
							onStartPracticeLab={handleDirectPracticeLaunch}
							onStartExternal={() => handleNavigate("external-workflow")}
							onStartApiAssessment={() => {
								setExtAllowedPaths("/api/,/rest/,/v1/");
								handleNavigate("external-workflow");
							}}
							onStartRetest={() => handleNavigate("findings", "issues")}
							onReviewFindings={() => handleNavigate("findings", "overview")}
							onSkipToDashboard={handleSkipOnboarding}
							isStartingPractice={isStartingPractice}
							managedLabs={managedLabs}
						/>
					)}

					{/* View 1: Dashboard */}
					{activeView === "dashboard" && (
						<DashboardView
							managedLabs={managedLabs}
							externalGrants={externalGrants}
							assessmentResults={assessmentResults}
							liveStatus={liveStatus}
							auditEvents={auditEvents}
							onNavigate={handleNavigate}
							onStartAssessment={handleStartAssessment}
							onStopLab={handleStopLab}
							isStoppingLab={isStoppingLab}
							copiedTarget={copiedTarget}
							onCopy={handleCopy}
							renderStatusBadge={renderStatusBadge}
						/>
					)}

					{/* View 2: Assessment Wizard (Practice Lab) */}
					{activeView === "assessment-wizard" && (
						<AssessmentWizardView
							managedLabs={managedLabs}
							externalGrants={externalGrants}
							onStartLab={handleStartLab}
							isStartingLab={isStartingLab}
							onStartAssessment={handleStartAssessment}
							isStartingRun={isStartingRun}
							onRegisterExternal={handleRegisterExternal}
							isRegisteringExt={isRegisteringExt}
							onNavigate={handleNavigate}
						/>
					)}

					{/* View 2.5: External Application Assessment */}
					{activeView === "external-workflow" && (
						<ExternalAssessmentWorkflowView
							profile={profile}
							externalGrants={externalGrants}
							onRegisterExternal={handleRegisterExternal}
							isRegisteringExt={isRegisteringExt}
							onStartAssessment={handleStartAssessment}
							isStartingRun={isStartingRun}
							onNavigate={handleNavigate}
						/>
					)}

					{/* View 3: Live Assessment Dashboard */}
					{activeView === "live-assessment" && (
						<LiveAssessmentView
							results={assessmentResults}
							liveStatus={liveStatus}
							managedLabs={managedLabs}
							onStartAssessment={handleStartAssessment}
							isStartingRun={isStartingRun || isStartingPractice}
							onStopAssessment={handleStopAssessment}
							isStoppingRun={isStoppingRun}
							onRefresh={handleRefreshAll}
							onNavigate={handleNavigate}
						/>
					)}

					{/* View 4: Findings & Coverage & Report */}
					{activeView === "findings" && (
						<FindingsView
							results={assessmentResults}
							onStartAssessment={handleStartAssessment}
							isStartingRun={isStartingRun}
							onNavigate={handleNavigate}
							initialSubTab={findingsSubTab}
						/>
					)}

					{/* View 5: Attack Path Map */}
					{activeView === "attack-path" && (
						<AttackPathView
							results={assessmentResults}
							onNavigate={handleNavigate}
						/>
					)}

					{/* View 6: Practice Lab */}
					{activeView === "practice-lab" && (
						<PracticeLabSection
							managedLabs={managedLabs}
							labDuration={labDuration}
							setLabDuration={setLabDuration}
							onStartLab={handleStartLab}
							isStartingLab={isStartingLab}
							onStopLab={handleStopLab}
							isStoppingLab={isStoppingLab}
							onStartAssessment={handleStartAssessment}
							copiedTarget={copiedTarget}
							onCopy={handleCopy}
							renderStatusBadge={renderStatusBadge}
						/>
					)}

					{/* View 7: External Targets */}
					{activeView === "external-targets" && (
						<ExternalTargetsSection
							profile={profile}
							externalGrants={externalGrants}
							extHost={extHost}
							setExtHost={setExtHost}
							extPort={extPort}
							setExtPort={setExtPort}
							extAllowedPaths={extAllowedPaths}
							setExtAllowedPaths={setExtAllowedPaths}
							extBlockedPaths={extBlockedPaths}
							setExtBlockedPaths={setExtBlockedPaths}
							selectedAssessmentId={selectedAssessmentId}
							setSelectedAssessmentId={setSelectedAssessmentId}
							dnsTokenInput={dnsTokenInput}
							setDnsTokenInput={setDnsTokenInput}
							evidenceRef={evidenceRef}
							setEvidenceRef={setEvidenceRef}
							onRegisterExternal={() => handleRegisterExternal()}
							isRegisteringExt={isRegisteringExt}
							onVerifyDNS={handleVerifyDNS}
							isVerifyingDNS={isVerifyingDNS}
							onApproveExternal={handleApproveExternal}
							isApprovingExt={isApprovingExt}
							onRevokeGrant={handleRevokeGrant}
							isRevokingGrant={isRevokingGrant}
							onStartAssessment={handleStartAssessment}
							renderStatusBadge={renderStatusBadge}
						/>
					)}

					{/* View 8: Audit Trail */}
					{activeView === "audit" && (
						<AuditTrailSection
							auditEvents={auditEvents}
							isLoading={isAuditLoading}
							onRefresh={refetchAudit}
						/>
					)}
				</main>
			</div>
		</div>
	);
}
