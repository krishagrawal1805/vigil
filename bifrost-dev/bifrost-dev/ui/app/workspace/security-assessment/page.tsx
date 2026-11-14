import { useState, useEffect } from "react";
import {
	Shield,
	ShieldAlert,
	ShieldCheck,
	AlertTriangle,
	Play,
	Square,
	RefreshCw,
	CheckCircle2,
	XCircle,
	Clock,
	Copy,
	Check,
	ExternalLink,
	Lock,
	FileText,
	Server,
	Cpu,
	HardDrive,
	Globe,
	Terminal,
	Layers,
	Eye,
	Ban,
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
	useGetCallerProfileQuery,
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
	type LabSession,
	type AuthorizationGrant,
} from "@/lib/store";

export default function SecurityAssessmentPage() {
	const [activeTab, setActiveTab] = useState<string>("overview");
	const [labDuration, setLabDuration] = useState<number>(60);
	const [copiedTarget, setCopiedTarget] = useState<boolean>(false);
	const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

	// External Assessment Form State
	const [extHost, setExtHost] = useState<string>("");
	const [extPort, setExtPort] = useState<number>(443);
	const [extAllowedPaths, setExtAllowedPaths] = useState<string>("/public/, /products/, /api/");
	const [extBlockedPaths, setExtBlockedPaths] = useState<string>("/admin/, /payments/, /users/private/");
	const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>("");
	const [dnsTokenInput, setDnsTokenInput] = useState<string>("");
	const [evidenceRef, setEvidenceRef] = useState<string>("");

	// Backend Queries
	const {
		data: callerProfile,
		isLoading: isProfileLoading,
		error: profileError,
		refetch: refetchProfile,
	} = useGetCallerProfileQuery();

	const {
		data: managedLabs,
		isLoading: isLabsLoading,
		refetch: refetchLabs,
	} = useGetManagedLabsQuery(undefined, { pollingInterval: 5000 });

	const {
		data: externalGrants,
		isLoading: isGrantsLoading,
		refetch: refetchGrants,
	} = useGetExternalAssessmentsQuery(undefined, { pollingInterval: 6000 });

	const {
		data: assessmentResults,
		isLoading: isResultsLoading,
		refetch: refetchResults,
	} = useGetAssessmentResultsQuery(undefined, { pollingInterval: 4000 });

	const {
		data: liveStatus,
		refetch: refetchStatus,
	} = useGetAssessmentStatusQuery(undefined, { pollingInterval: 2500 });

	const {
		data: auditEvents,
		isLoading: isAuditLoading,
		refetch: refetchAudit,
	} = useGetLabAuditEventsQuery(undefined, { pollingInterval: 8000 });

	// Backend Mutations
	const [startLab, { isLoading: isStartingLab }] = useStartManagedLabMutation();
	const [stopLab, { isLoading: isStoppingLab }] = useStopManagedLabMutation();
	const [registerExternal, { isLoading: isRegisteringExt }] = useRegisterExternalAssessmentMutation();
	const [verifyDNS, { isLoading: isVerifyingDNS }] = useVerifyExternalDNSMutation();
	const [approveExternal, { isLoading: isApprovingExt }] = useApproveExternalAssessmentMutation();
	const [revokeGrant, { isLoading: isRevokingGrant }] = useRevokeGrantMutation();
	const [startAssessmentRun, { isLoading: isStartingRun }] = useStartAssessmentRunMutation();
	const [stopAssessmentRun, { isLoading: isStoppingRun }] = useStopAssessmentRunMutation();

	const activeLab = managedLabs?.find((l) => l.status === "running");

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
				text: `Managed lab ${res.lab_session.lab_instance_id} started at ${res.lab_session.target_url}`,
			});
			refetchLabs();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "Failed to start practice lab",
			});
		}
	};

	const handleStopLab = async (labInstanceId: string) => {
		setActionMessage(null);
		try {
			await stopLab({ lab_instance_id: labInstanceId }).unwrap();
			setActionMessage({
				type: "success",
				text: `Practice lab ${labInstanceId} stopped and authorization grant revoked.`,
			});
			refetchLabs();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "Failed to stop lab (verify ownership/permissions)",
			});
		}
	};

	const handleRegisterExternal = async () => {
		if (!extHost.trim()) {
			setActionMessage({ type: "error", text: "Target host is mandatory" });
			return;
		}
		setActionMessage(null);
		try {
			const allowedPaths = extAllowedPaths.split(",").map((p) => p.trim()).filter(Boolean);
			const blockedPaths = extBlockedPaths.split(",").map((p) => p.trim()).filter(Boolean);
			const res = await registerExternal({
				target_host: extHost.trim(),
				target_port: extPort,
				allowed_paths: allowedPaths,
				blocked_paths: blockedPaths,
			}).unwrap();

			setSelectedAssessmentId(res.grant.assessment_id);
			setDnsTokenInput(res.grant.dns_challenge_token || "");
			setActionMessage({
				type: "success",
				text: `Registered target ${res.grant.authorized_host}. Complete DNS challenge before requesting approval.`,
			});
			refetchGrants();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "Failed to register external assessment",
			});
		}
	};

	const handleVerifyDNS = async (asmId: string, token: string) => {
		setActionMessage(null);
		try {
			const res = await verifyDNS({ assessment_id: asmId, token }).unwrap();
			setActionMessage({
				type: "success",
				text: res.message || "DNS control verified. Now submit owner authorization evidence.",
			});
			refetchGrants();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "DNS verification failed",
			});
		}
	};

	const handleApproveExternal = async (asmId: string) => {
		if (!evidenceRef.trim()) {
			setActionMessage({
				type: "error",
				text: "Authorization Evidence Reference is mandatory for formal approval.",
			});
			return;
		}
		setActionMessage(null);
		try {
			const res = await approveExternal({
				assessment_id: asmId,
				auth_evidence_ref: evidenceRef.trim(),
				duration: 14400000000000, // 4 hours in ns
			}).unwrap();
			setActionMessage({
				type: "success",
				text: `Authorization grant ${res.grant_id} approved and activated for ${res.authorized_host}!`,
			});
			setEvidenceRef("");
			refetchGrants();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "Authorization approval rejected",
			});
		}
	};

	const handleRevokeGrant = async (grantId: string) => {
		setActionMessage(null);
		try {
			await revokeGrant({ grant_id: grantId, reason: "Operator manual revocation via frontend" }).unwrap();
			setActionMessage({ type: "success", text: `Grant ${grantId} revoked successfully.` });
			refetchGrants();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "Failed to revoke grant",
			});
		}
	};

	const handleStartAssessment = async (grantId?: string) => {
		setActionMessage(null);
		try {
			const res = await startAssessmentRun({ grant_id: grantId }).unwrap();
			setActionMessage({
				type: "success",
				text: `Autonomous pentesting initiated against ${res.target} under grant ${res.grant_id} (Run: ${res.run_id || "started"}).`,
			});
			setActiveTab("results");
			refetchResults();
			refetchStatus();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "Cannot start assessment (grant not approved or expired)",
			});
		}
	};

	const handleStopAssessment = async (runId?: string) => {
		setActionMessage(null);
		try {
			await stopAssessmentRun({ run_id: runId, reason: "Operator cancelled run from dashboard" }).unwrap();
			setActionMessage({
				type: "success",
				text: "Assessment run cancelled successfully.",
			});
			refetchResults();
			refetchStatus();
		} catch (err: any) {
			setActionMessage({
				type: "error",
				text: err?.data?.error?.message || err?.message || "Failed to cancel assessment run",
			});
		}
	};

	const renderStatusBadge = (status: string) => {
		switch (status) {
			case "approved":
			case "running":
				return <Badge className="bg-emerald-600 hover:bg-emerald-700 text-white font-medium">Approved / Active</Badge>;
			case "dns_verified_pending_approval":
				return <Badge className="bg-blue-600 hover:bg-blue-700 text-white font-medium">DNS Verified (Pending Approval)</Badge>;
			case "pending":
			case "starting":
				return <Badge className="bg-amber-600 hover:bg-amber-700 text-white font-medium">Pending</Badge>;
			case "revoked":
				return <Badge variant="destructive">Revoked</Badge>;
			case "expired":
			case "stopped":
				return <Badge variant="secondary">Expired / Stopped</Badge>;
			default:
				return <Badge variant="outline">{status}</Badge>;
		}
	};

	return (
		<div className="flex flex-col gap-6 p-6 max-w-7xl mx-auto w-full">
			{/* Top Header & Caller Profile Badge */}
			<div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b pb-5">
				<div>
					<div className="flex items-center gap-2.5">
						<div className="p-2 rounded-lg bg-primary/10 text-primary">
							<ShieldCheck className="h-6 w-6" />
						</div>
						<h1 className="text-2xl font-bold tracking-tight">Security Assessment & Autonomous Pentesting</h1>
					</div>
					<p className="text-muted-foreground text-sm mt-1">
						Enterprise security gateway powered by Bifrost ScopeEnforcer & Strix autonomous reasoning
					</p>
				</div>

				<div className="flex items-center gap-3">
					{/* Server-Validated Session Identity Badge */}
					<div className="flex items-center gap-2 px-3.5 py-1.5 rounded-md border bg-muted/40 text-xs">
						<div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
						<span className="font-semibold text-foreground">
							{callerProfile?.user_id || "Authenticating..."}
						</span>
						<span className="text-muted-foreground">•</span>
						<span className="text-muted-foreground font-mono">{callerProfile?.org_id || "Loading org"}</span>
						<Badge variant="outline" className="text-[10px] h-4 px-1 uppercase font-semibold">
							{callerProfile?.role || "user"}
						</Badge>
					</div>

					<Button
						variant="outline"
						size="sm"
						onClick={() => {
							refetchProfile();
							refetchLabs();
							refetchGrants();
							refetchResults();
							refetchAudit();
						}}
						className="gap-1.5"
					>
						<RefreshCw className="h-3.5 w-3.5" />
						Refresh
					</Button>
				</div>
			</div>

			{/* Global Notifications / Alert Banner */}
			{actionMessage && (
				<Alert variant={actionMessage.type === "error" ? "destructive" : "default"}>
					{actionMessage.type === "error" ? (
						<AlertTriangle className="h-4 w-4" />
					) : (
						<CheckCircle2 className="h-4 w-4 text-emerald-500" />
					)}
					<AlertTitle>{actionMessage.type === "error" ? "Action Blocked / Error" : "Success"}</AlertTitle>
					<AlertDescription>{actionMessage.text}</AlertDescription>
				</Alert>
			)}

			{/* Authentication Warning if session not valid */}
			{Boolean(profileError) && (
				<Alert variant="destructive">
					<Lock className="h-4 w-4" />
					<AlertTitle>Authentication Required</AlertTitle>
					<AlertDescription>
						Your dashboard session is unauthenticated. Please log into the Bifrost dashboard to manage practice labs
						and execute security assessments.
					</AlertDescription>
				</Alert>
			)}

			{/* Main Workspace Tabs */}
			<Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
				<TabsList className="grid grid-cols-2 md:grid-cols-5 w-full md:w-auto h-auto p-1 bg-muted/60">
					<TabsTrigger value="overview" className="gap-2 py-2">
						<Layers className="h-4 w-4" />
						<span>Overview</span>
					</TabsTrigger>
					<TabsTrigger value="practice-lab" className="gap-2 py-2">
						<Server className="h-4 w-4" />
						<span>Practice Lab</span>
						{activeLab && (
							<span className="h-2 w-2 rounded-full bg-emerald-500" title="Active Lab Running" />
						)}
					</TabsTrigger>
					<TabsTrigger value="external" className="gap-2 py-2">
						<Globe className="h-4 w-4" />
						<span>External Targets</span>
					</TabsTrigger>
					<TabsTrigger value="results" className="gap-2 py-2">
						<FileText className="h-4 w-4" />
						<span>Pentest Results</span>
					</TabsTrigger>
					<TabsTrigger value="audit" className="gap-2 py-2">
						<Terminal className="h-4 w-4" />
						<span>Audit Trail</span>
					</TabsTrigger>
				</TabsList>

				{/* TAB 1: MAIN DASHBOARD OVERVIEW */}
				<TabsContent value="overview" className="space-y-6 mt-6">
					{/* Stat Metric Cards */}
					<div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
						<Card>
							<CardHeader className="flex flex-row items-center justify-between pb-2">
								<CardTitle className="text-sm font-medium">Practice Labs</CardTitle>
								<Server className="h-4 w-4 text-muted-foreground" />
							</CardHeader>
							<CardContent>
								<div className="text-2xl font-bold">
									{managedLabs?.filter((l) => l.status === "running").length || 0}
								</div>
								<p className="text-xs text-muted-foreground mt-1">Active isolated containers</p>
							</CardContent>
						</Card>

						<Card>
							<CardHeader className="flex flex-row items-center justify-between pb-2">
								<CardTitle className="text-sm font-medium">External Authorizations</CardTitle>
								<Globe className="h-4 w-4 text-muted-foreground" />
							</CardHeader>
							<CardContent>
								<div className="text-2xl font-bold">
									{externalGrants?.filter((g) => g.approval_status === "approved" && !g.is_revoked).length || 0}
								</div>
								<p className="text-xs text-muted-foreground mt-1">
									{externalGrants?.filter((g) => g.approval_status === "pending").length || 0} pending challenge
								</p>
							</CardContent>
						</Card>

						<Card>
							<CardHeader className="flex flex-row items-center justify-between pb-2">
								<CardTitle className="text-sm font-medium">Identified Vulnerabilities</CardTitle>
								<ShieldAlert className="h-4 w-4 text-rose-500" />
							</CardHeader>
							<CardContent>
								<div className="text-2xl font-bold text-rose-600">
									{assessmentResults?.findings?.length || 0}
								</div>
								<p className="text-xs text-muted-foreground mt-1">Confirmed across scope</p>
							</CardContent>
						</Card>

						<Card>
							<CardHeader className="flex flex-row items-center justify-between pb-2">
								<CardTitle className="text-sm font-medium">Scope Violations Blocked</CardTitle>
								<Ban className="h-4 w-4 text-amber-500" />
							</CardHeader>
							<CardContent>
								<div className="text-2xl font-bold text-amber-600">
									{assessmentResults?.blocked_requests?.length || 0}
								</div>
								<p className="text-xs text-muted-foreground mt-1">Intercepted by ScopeEnforcer</p>
							</CardContent>
						</Card>
					</div>

					{/* Security Gateway Enforcer Status Card */}
					<Card className="border-primary/20 bg-primary/[0.02]">
						<CardHeader>
							<div className="flex items-center justify-between">
								<div className="flex items-center gap-2">
									<Shield className="h-5 w-5 text-primary" />
									<CardTitle className="text-base font-semibold">Active Gateway Enforcement Model</CardTitle>
								</div>
								<Badge className="bg-emerald-600 text-white font-mono text-xs">SCOPE_ENFORCER_ACTIVE</Badge>
							</div>
							<CardDescription>
								Bifrost dynamically validates every outbound HTTP request against cryptographic authorization grants.
							</CardDescription>
						</CardHeader>
						<CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
							<div className="p-3 rounded-lg border bg-background space-y-1">
								<div className="font-semibold text-foreground flex items-center gap-1.5">
									<Cpu className="h-3.5 w-3.5 text-primary" />
									Target Egress Isolation
								</div>
								<p className="text-muted-foreground">
									Containers run on isolated bridge (<span className="font-mono">strix-lab-net</span>). WAN default
									routes are stripped; outbound metadata is unreachable.
								</p>
							</div>

							<div className="p-3 rounded-lg border bg-background space-y-1">
								<div className="font-semibold text-foreground flex items-center gap-1.5">
									<Lock className="h-3.5 w-3.5 text-primary" />
									Grant Bound Verification
								</div>
								<p className="text-muted-foreground">
									Grants bind to exact ContainerID, TargetHost, Port, Allowed Paths, and Methods. Direct client grant
									minting is forbidden.
								</p>
							</div>

							<div className="p-3 rounded-lg border bg-background space-y-1">
								<div className="font-semibold text-foreground flex items-center gap-1.5">
									<HardDrive className="h-3.5 w-3.5 text-primary" />
									Resource Caps & Janitor
								</div>
								<p className="text-muted-foreground">
									Containers strictly capped at 512MB RAM, 1.0 CPU, 200 PIDs. Background janitor auto-cleans expired
									sessions every 20s.
								</p>
							</div>
						</CardContent>
					</Card>

					{/* Active Practice Labs Quick Overview */}
					<Card>
						<CardHeader className="flex flex-row items-center justify-between">
							<div>
								<CardTitle className="text-base">Managed Practice Labs</CardTitle>
								<CardDescription>Currently running intentionally vulnerable target environments</CardDescription>
							</div>
							<Button size="sm" onClick={() => setActiveTab("practice-lab")} className="gap-1.5">
								<Server className="h-4 w-4" />
								Open Lab Manager
							</Button>
						</CardHeader>
						<CardContent>
							{managedLabs && managedLabs.length > 0 ? (
								<Table>
									<TableHeader>
										<TableRow>
											<TableHead>Instance ID</TableHead>
											<TableHead>Target Address</TableHead>
											<TableHead>Container ID</TableHead>
											<TableHead>Status</TableHead>
											<TableHead>Expires</TableHead>
											<TableHead className="text-right">Actions</TableHead>
										</TableRow>
									</TableHeader>
									<TableBody>
										{managedLabs.map((lab) => (
											<TableRow key={lab.lab_instance_id}>
												<TableCell className="font-mono text-xs font-semibold">{lab.lab_instance_id}</TableCell>
												<TableCell>
													<div className="flex items-center gap-1.5 font-mono text-xs">
														<span>{lab.target_url}</span>
														<button
															onClick={() => handleCopy(lab.target_url)}
															className="text-muted-foreground hover:text-foreground"
															title="Copy Target URL"
														>
															<Copy className="h-3 w-3" />
														</button>
													</div>
												</TableCell>
												<TableCell className="font-mono text-xs">{lab.container_id}</TableCell>
												<TableCell>{renderStatusBadge(lab.status)}</TableCell>
												<TableCell className="text-xs text-muted-foreground">
													{new Date(lab.expires_at).toLocaleTimeString()}
												</TableCell>
												<TableCell className="text-right space-x-2">
													{lab.status === "running" && (
														<>
															<Button
																variant="default"
																size="sm"
																onClick={() => handleStartAssessment(lab.grant_id)}
																className="gap-1 text-xs"
															>
																<Play className="h-3 w-3" />
																Run Pentest
															</Button>
															<Button
																variant="outline"
																size="sm"
																onClick={() => handleStopLab(lab.lab_instance_id)}
																disabled={isStoppingLab}
																className="text-destructive hover:bg-destructive/10 text-xs"
															>
																<Square className="h-3 w-3" />
																Stop
															</Button>
														</>
													)}
												</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							) : (
								<div className="text-center py-8 text-muted-foreground text-sm">
									No practice labs currently running. Launch OWASP Juice Shop from the Practice Lab tab.
								</div>
							)}
						</CardContent>
					</Card>
				</TabsContent>

				{/* TAB 2: MANAGED PRACTICE LAB */}
				<TabsContent value="practice-lab" className="space-y-6 mt-6">
					<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
						{/* Target Spec & Launch Card */}
						<Card className="lg:col-span-1">
							<CardHeader>
								<div className="flex items-center justify-between">
									<CardTitle className="text-base">Target Application</CardTitle>
									<Badge variant="secondary">OWASP Juice Shop</Badge>
								</div>
								<CardDescription>
									Official intentionally vulnerable training target pinned to immutable digest.
								</CardDescription>
							</CardHeader>
							<CardContent className="space-y-4 text-xs">
								<div className="space-y-2 border rounded-lg p-3 bg-muted/20">
									<div className="flex justify-between">
										<span className="text-muted-foreground">Version:</span>
										<span className="font-semibold">v20.3.0</span>
									</div>
									<div className="flex justify-between">
										<span className="text-muted-foreground">Base Image:</span>
										<span className="font-mono text-[10px]">bkimminich/juice-shop:v20.3.0</span>
									</div>
									<div className="flex justify-between">
										<span className="text-muted-foreground">Digest:</span>
										<span className="font-mono text-[10px]">sha256:42843723...</span>
									</div>
									<div className="flex justify-between">
										<span className="text-muted-foreground">Memory Cap:</span>
										<span>512 MB</span>
									</div>
									<div className="flex justify-between">
										<span className="text-muted-foreground">CPU Quota:</span>
										<span>1.0 Core</span>
									</div>
									<div className="flex justify-between">
										<span className="text-muted-foreground">Network Egress:</span>
										<span className="text-rose-600 font-semibold">WAN Disabled (ENETUNREACH)</span>
									</div>
								</div>

								<div className="space-y-2">
									<Label htmlFor="duration" className="text-xs">
										Assessment Window Duration
									</Label>
									<select
										id="duration"
										value={labDuration}
										onChange={(e) => setLabDuration(Number(e.target.value))}
										className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs shadow-sm"
									>
										<option value={30}>30 Minutes</option>
										<option value={60}>1 Hour</option>
										<option value={120}>2 Hours</option>
										<option value={240}>4 Hours</option>
									</select>
									<p className="text-[11px] text-muted-foreground">
										Containers are automatically destroyed and authorization grants revoked upon expiration.
									</p>
								</div>
							</CardContent>
							<CardFooter>
								<Button
									onClick={handleStartLab}
									disabled={isStartingLab || !!activeLab}
									className="w-full gap-2"
								>
									{isStartingLab ? (
										<>
											<RefreshCw className="h-4 w-4 animate-spin" />
											Provisioning Container...
										</>
									) : (
										<>
											<Play className="h-4 w-4" />
											{activeLab ? "Lab Already Running" : "Launch Practice Lab"}
										</>
									)}
								</Button>
							</CardFooter>
						</Card>

						{/* Active Target State & Scope Card */}
						<Card className="lg:col-span-2">
							<CardHeader>
								<div className="flex items-center justify-between">
									<div>
										<CardTitle className="text-base">Active Managed Target State</CardTitle>
										<CardDescription>Dynamic loopback binding and ScopeEnforcer policy</CardDescription>
									</div>
									{activeLab ? (
										<Badge className="bg-emerald-600 text-white gap-1.5">
											<span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
											RUNNING
										</Badge>
									) : (
										<Badge variant="outline">NO ACTIVE LAB</Badge>
									)}
								</div>
							</CardHeader>
							<CardContent className="space-y-4">
								{activeLab ? (
									<div className="space-y-4">
										{/* Target Connection Bar */}
										<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-lg border bg-muted/30">
											<div>
												<div className="text-xs text-muted-foreground font-medium">Assigned Loopback URL</div>
												<div className="text-lg font-mono font-bold text-foreground mt-0.5">
													{activeLab.target_url}
												</div>
											</div>
											<div className="flex items-center gap-2">
												<Button
													variant="outline"
													size="sm"
													onClick={() => handleCopy(activeLab.target_url)}
													className="gap-1.5 text-xs"
												>
													{copiedTarget ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
													{copiedTarget ? "Copied" : "Copy Target"}
												</Button>
												<Button
													variant="secondary"
													size="sm"
													asChild
													className="gap-1.5 text-xs"
												>
													<a href={activeLab.target_url} target="_blank" rel="noopener noreferrer">
														<ExternalLink className="h-3.5 w-3.5" />
														Open Target
													</a>
												</Button>
											</div>
										</div>

										{/* Session Metadata Grid */}
										<div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
											<div className="border rounded-md p-2.5 bg-background">
												<div className="text-muted-foreground">Lab Instance</div>
												<div className="font-mono font-semibold truncate mt-0.5">{activeLab.lab_instance_id}</div>
											</div>
											<div className="border rounded-md p-2.5 bg-background">
												<div className="text-muted-foreground">Container ID</div>
												<div className="font-mono font-semibold truncate mt-0.5">{activeLab.container_id}</div>
											</div>
											<div className="border rounded-md p-2.5 bg-background">
												<div className="text-muted-foreground">Target Port</div>
												<div className="font-mono font-semibold mt-0.5">{activeLab.target_port}</div>
											</div>
											<div className="border rounded-md p-2.5 bg-background">
												<div className="text-muted-foreground">Expiration</div>
												<div className="font-semibold text-amber-600 mt-0.5">
													{new Date(activeLab.expires_at).toLocaleTimeString()}
												</div>
											</div>
										</div>

										{/* Approved Scope Rules Table */}
										<div className="border rounded-lg p-3.5 space-y-2 bg-background">
											<div className="text-xs font-semibold flex items-center gap-1.5">
												<Lock className="h-3.5 w-3.5 text-primary" />
												Authorization Scope Restrictions
											</div>
											<div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
												<div>
													<span className="text-muted-foreground">Allowed CIDRs:</span>
													<div className="font-mono text-emerald-600 mt-0.5">127.0.0.1/32</div>
												</div>
												<div>
													<span className="text-muted-foreground">Allowed Methods:</span>
													<div className="font-mono text-emerald-600 mt-0.5">GET, HEAD, POST, OPTIONS</div>
												</div>
												<div>
													<span className="text-muted-foreground">Allowed Paths:</span>
													<div className="font-mono text-emerald-600 text-[11px] mt-0.5">
														/, /api/, /rest/, /assets/, /ftp/, /public/
													</div>
												</div>
												<div>
													<span className="text-muted-foreground">Blocked Paths:</span>
													<div className="font-mono text-rose-600 text-[11px] mt-0.5">
														/forbidden/admin/, /internal/super-secret/
													</div>
												</div>
											</div>
										</div>

										{/* Action Buttons */}
										<div className="flex items-center justify-end gap-3 pt-2">
											<Button
												variant="destructive"
												size="sm"
												onClick={() => handleStopLab(activeLab.lab_instance_id)}
												disabled={isStoppingLab}
												className="gap-1.5"
											>
												<Square className="h-3.5 w-3.5" />
												Terminate Practice Lab
											</Button>
											<Button
												variant="default"
												size="sm"
												onClick={() => handleStartAssessment(activeLab.grant_id)}
												disabled={isStartingRun}
												className="gap-1.5"
											>
												<Play className="h-3.5 w-3.5" />
												Launch Autonomous Pentest
											</Button>
										</div>
									</div>
								) : (
									<div className="flex flex-col items-center justify-center py-12 text-center text-muted-foreground">
										<Server className="h-10 w-10 text-muted-foreground/40 mb-3" />
										<p className="font-medium">No practice lab is currently running.</p>
										<p className="text-xs text-muted-foreground mt-1 max-w-md">
											Click "Launch Practice Lab" to deploy an air-gapped OWASP Juice Shop instance. The backend
											orchestrator will automatically bind dynamic ports and mint an authorized grant.
										</p>
									</div>
								)}
							</CardContent>
						</Card>
					</div>
				</TabsContent>

				{/* TAB 3: EXTERNAL WEBSITE ASSESSMENT */}
				<TabsContent value="external" className="space-y-6 mt-6">
					{/* Policy Banner */}
					<Alert className="border-amber-500/30 bg-amber-500/5">
						<AlertTriangle className="h-4 w-4 text-amber-500" />
						<AlertTitle className="text-amber-600 font-semibold">Strict Verification & Approval Policy</AlertTitle>
						<AlertDescription className="text-xs text-muted-foreground mt-1">
							External target assessments require two independent verification gates:
							<strong> (1) DNS TXT Ownership Challenge</strong> proving domain control, followed by
							<strong> (2) Formal Owner / Org-Admin Authorization Approval</strong> with an immutable evidence reference.
							DNS verification alone never authorizes penetration testing.
						</AlertDescription>
					</Alert>

					<div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
						{/* Step 1: Submit Target Form */}
						<Card>
							<CardHeader>
								<CardTitle className="text-base">Step 1: Submit Target Domain</CardTitle>
								<CardDescription>Register an external domain for ownership verification challenge</CardDescription>
							</CardHeader>
							<CardContent className="space-y-3.5 text-xs">
								<div className="grid grid-cols-3 gap-3">
									<div className="col-span-2 space-y-1.5">
										<Label htmlFor="ext-host">Target Domain / Hostname</Label>
										<Input
											id="ext-host"
											placeholder="e.g. staging.yourcompany.com"
											value={extHost}
											onChange={(e) => setExtHost(e.target.value)}
										/>
									</div>
									<div className="space-y-1.5">
										<Label htmlFor="ext-port">Target Port</Label>
										<Input
											id="ext-port"
											type="number"
											value={extPort}
											onChange={(e) => setExtPort(Number(e.target.value))}
										/>
									</div>
								</div>

								<div className="space-y-1.5">
									<Label htmlFor="ext-allowed">Allowed URL Paths (Scope Allowlist)</Label>
									<Input
										id="ext-allowed"
										value={extAllowedPaths}
										onChange={(e) => setExtAllowedPaths(e.target.value)}
									/>
								</div>

								<div className="space-y-1.5">
									<Label htmlFor="ext-blocked">Blocked URL Paths (Strictly Forbidden)</Label>
									<Input
										id="ext-blocked"
										value={extBlockedPaths}
										onChange={(e) => setExtBlockedPaths(e.target.value)}
									/>
								</div>
							</CardContent>
							<CardFooter>
								<Button
									onClick={handleRegisterExternal}
									disabled={isRegisteringExt || !extHost.trim()}
									className="w-full gap-2 text-xs"
								>
									{isRegisteringExt ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Globe className="h-3.5 w-3.5" />}
									Generate DNS Ownership Challenge
								</Button>
							</CardFooter>
						</Card>

						{/* Step 2 & 3: Challenge & Formal Approval */}
						<Card>
							<CardHeader>
								<CardTitle className="text-base">Step 2 & 3: Verification & Formal Approval</CardTitle>
								<CardDescription>Validate DNS ownership and submit signed authorization evidence</CardDescription>
							</CardHeader>
							<CardContent className="space-y-4 text-xs">
								{/* DNS Verification Section */}
								<div className="border rounded-lg p-3 space-y-2 bg-muted/20">
									<div className="font-semibold text-foreground flex items-center justify-between">
										<span>DNS TXT Ownership Challenge</span>
										<Badge variant="outline" className="text-[10px]">Step 2</Badge>
									</div>
									<div className="space-y-1.5">
										<Label htmlFor="challenge-id">Assessment ID</Label>
										<Input
											id="challenge-id"
											placeholder="asm-ext-..."
											value={selectedAssessmentId}
											onChange={(e) => setSelectedAssessmentId(e.target.value)}
										/>
									</div>
									<div className="space-y-1.5">
										<Label htmlFor="dns-token">DNS TXT Token</Label>
										<Input
											id="dns-token"
											placeholder="strix-auth-..."
											value={dnsTokenInput}
											onChange={(e) => setDnsTokenInput(e.target.value)}
										/>
									</div>
									<Button
										variant="secondary"
										size="sm"
										onClick={() => handleVerifyDNS(selectedAssessmentId, dnsTokenInput)}
										disabled={isVerifyingDNS || !selectedAssessmentId || !dnsTokenInput}
										className="w-full mt-1 text-xs gap-1.5"
									>
										{isVerifyingDNS ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
										Verify DNS TXT Record
									</Button>
								</div>

								{/* Formal Approval Section */}
								<div className="border rounded-lg p-3 space-y-2 bg-muted/20">
									<div className="font-semibold text-foreground flex items-center justify-between">
										<span>Formal Authorization Approval</span>
										<Badge variant="outline" className="text-[10px]">Step 3</Badge>
									</div>
									<div className="space-y-1.5">
										<Label htmlFor="evidence-ref">Authorization Evidence Reference (Contract / Document Hash)</Label>
										<Input
											id="evidence-ref"
											placeholder="e.g. SOW-2026-PENTEST-ACME-001 or doc_hash:e3b0c44..."
											value={evidenceRef}
											onChange={(e) => setEvidenceRef(e.target.value)}
										/>
										<p className="text-[10px] text-muted-foreground">
											Required by backend security policy. Proves signed consent by target owner.
										</p>
									</div>
									<Button
										variant="default"
										size="sm"
										onClick={() => handleApproveExternal(selectedAssessmentId)}
										disabled={isApprovingExt || !selectedAssessmentId || !evidenceRef.trim()}
										className="w-full mt-1 text-xs gap-1.5"
									>
										{isApprovingExt ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
										Issue Formal Authorization Grant
									</Button>
								</div>
							</CardContent>
						</Card>
					</div>

					{/* External Grants Table */}
					<Card>
						<CardHeader>
							<CardTitle className="text-base">Registered External Assessment Grants</CardTitle>
							<CardDescription>Tenancy-isolated authorization records for external websites</CardDescription>
						</CardHeader>
						<CardContent>
							{externalGrants && externalGrants.length > 0 ? (
								<Table>
									<TableHeader>
										<TableRow>
											<TableHead>Target Host</TableHead>
											<TableHead>Assessment ID</TableHead>
											<TableHead>DNS Control</TableHead>
											<TableHead>Approval Status</TableHead>
											<TableHead>Evidence Ref</TableHead>
											<TableHead className="text-right">Actions</TableHead>
										</TableRow>
									</TableHeader>
									<TableBody>
										{externalGrants.map((g) => (
											<TableRow key={g.grant_id}>
												<TableCell className="font-semibold text-xs">{g.authorized_host}:{g.authorized_port}</TableCell>
												<TableCell className="font-mono text-xs">{g.assessment_id}</TableCell>
												<TableCell>
													{g.dns_verified ? (
														<span className="text-emerald-600 font-medium text-xs flex items-center gap-1">
															<CheckCircle2 className="h-3.5 w-3.5" /> Verified
														</span>
													) : (
														<span className="text-amber-600 font-medium text-xs flex items-center gap-1">
															<Clock className="h-3.5 w-3.5" /> Pending TXT
														</span>
													)}
												</TableCell>
												<TableCell>{renderStatusBadge(g.approval_status)}</TableCell>
												<TableCell className="font-mono text-xs text-muted-foreground truncate max-w-[180px]">
													{g.auth_evidence_ref || "None"}
												</TableCell>
												<TableCell className="text-right space-x-2">
													{g.approval_status === "approved" && !g.is_revoked && (
														<>
															<Button
																variant="default"
																size="sm"
																onClick={() => handleStartAssessment(g.grant_id)}
																className="text-xs gap-1"
															>
																<Play className="h-3 w-3" />
																Start Pentest
															</Button>
															<Button
																variant="outline"
																size="sm"
																onClick={() => handleRevokeGrant(g.grant_id)}
																className="text-xs text-destructive hover:bg-destructive/10"
															>
																Revoke
															</Button>
														</>
													)}
													{g.approval_status === "pending" && (
														<Button
															variant="outline"
															size="sm"
															onClick={() => {
																setSelectedAssessmentId(g.assessment_id);
																setDnsTokenInput(g.dns_challenge_token || "");
															}}
															className="text-xs"
														>
															Verify DNS
														</Button>
													)}
													{g.approval_status === "dns_verified_pending_approval" && (
														<Button
															variant="secondary"
															size="sm"
															onClick={() => setSelectedAssessmentId(g.assessment_id)}
															className="text-xs"
														>
															Approve
														</Button>
													)}
												</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							) : (
								<div className="text-center py-8 text-muted-foreground text-sm">
									No external targets registered yet. Register an external website above to start authorization.
								</div>
							)}
						</CardContent>
					</Card>
				</TabsContent>

				{/* TAB 4: ASSESSMENT RESULTS & FINDINGS */}
				<TabsContent value="results" className="space-y-6 mt-6">
					{assessmentResults ? (
						<>
							{/* Live Assessment Alert Banner */}
							{(assessmentResults.status === "running" || assessmentResults.status === "starting") && (
								<Alert className="border-blue-500/40 bg-blue-500/5">
									<RefreshCw className="h-4 w-4 text-blue-500 animate-spin" />
									<AlertTitle className="text-blue-600 font-semibold flex items-center justify-between">
										<span>Autonomous Pentesting Mission in Progress</span>
										{assessmentResults.pid && (
											<Badge variant="outline" className="font-mono text-[10px]">
												PID: {assessmentResults.pid}
											</Badge>
										)}
									</AlertTitle>
									<AlertDescription className="text-xs text-muted-foreground mt-1 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
										<span>
											Strix agent is actively interrogating <strong>{assessmentResults.target}</strong> under verified authorization grant {assessmentResults.grant_id}. Every request is validated by FineGrainedScopeEnforcer.
										</span>
										<Button
											variant="destructive"
											size="sm"
											onClick={() => handleStopAssessment(assessmentResults.run_id)}
											disabled={isStoppingRun}
											className="gap-1.5 h-7 text-xs self-start sm:self-auto"
										>
											<Square className="h-3 w-3" />
											Stop Assessment
										</Button>
									</AlertDescription>
								</Alert>
							)}

							{/* Target & Scope Banner */}
							<Card>
								<CardHeader>
									<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
										<div>
											<div className="flex items-center gap-2">
												<CardTitle className="text-lg">Assessment Findings Report</CardTitle>
												<Badge
													className={
														assessmentResults.status === "completed"
															? "bg-emerald-600 text-white font-mono text-xs"
															: assessmentResults.status === "running" || assessmentResults.status === "starting"
															? "bg-blue-600 text-white font-mono text-xs animate-pulse"
															: assessmentResults.status === "cancelled"
															? "bg-amber-600 text-white font-mono text-xs"
															: "bg-muted text-muted-foreground font-mono text-xs"
													}
												>
													{assessmentResults.status.toUpperCase()}
												</Badge>
												{assessmentResults.agent_model && (
													<Badge variant="outline" className="font-mono text-[10px]">
														{assessmentResults.agent_model}
													</Badge>
												)}
											</div>
											<CardDescription className="font-mono text-xs mt-1">
												Target: {assessmentResults.target} • Grant: {assessmentResults.grant_id}
												{assessmentResults.run_id && ` • Run: ${assessmentResults.run_id}`}
											</CardDescription>
										</div>
										<div className="flex items-center gap-2">
											{assessmentResults.status === "running" || assessmentResults.status === "starting" ? (
												<Button
													variant="destructive"
													size="sm"
													onClick={() => handleStopAssessment(assessmentResults.run_id)}
													disabled={isStoppingRun}
													className="gap-1.5"
												>
													<Square className="h-3.5 w-3.5" />
													Stop Assessment
												</Button>
											) : (
												<Button
													size="sm"
													onClick={() => handleStartAssessment(assessmentResults.grant_id)}
													disabled={isStartingRun}
													className="gap-1.5"
												>
													<Play className="h-3.5 w-3.5" />
													Re-run Assessment
												</Button>
											)}
										</div>
									</div>
								</CardHeader>
								<CardContent className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
									<div className="border rounded-md p-3 bg-muted/20">
										<div className="text-muted-foreground">Start Time</div>
										<div className="font-semibold mt-0.5">
											{assessmentResults.start_time ? new Date(assessmentResults.start_time).toLocaleTimeString() : "—"}
										</div>
									</div>
									<div className="border rounded-md p-3 bg-muted/20">
										<div className="text-muted-foreground">Duration</div>
										<div className="font-semibold mt-0.5">
											{assessmentResults.duration_seconds !== undefined
												? `${assessmentResults.duration_seconds}s`
												: assessmentResults.end_time
												? new Date(assessmentResults.end_time).toLocaleTimeString()
												: "In progress"}
										</div>
									</div>
									<div className="border rounded-md p-3 bg-muted/20">
										<div className="text-muted-foreground">Tools Executed</div>
										<div className="font-semibold mt-0.5">
											{assessmentResults.tools_executed.length > 0
												? assessmentResults.tools_executed.map((t) => t.tool).join(", ")
												: "Pending tool execution"}
										</div>
									</div>
									<div className="border rounded-md p-3 bg-muted/20">
										<div className="text-muted-foreground">Scope Enforcement</div>
										<div className="font-semibold text-emerald-600 mt-0.5">
											{assessmentResults.blocked_requests.length} Out-of-Scope Blocks
										</div>
									</div>
								</CardContent>
							</Card>

							{/* Executive Report Summary if available */}
							{assessmentResults.final_report && (
								<Card className="border-primary/20 bg-primary/[0.02]">
									<CardHeader className="pb-2">
										<div className="flex items-center gap-2">
											<FileText className="h-4 w-4 text-primary" />
											<CardTitle className="text-sm">Strix Autonomous Assessment Summary</CardTitle>
										</div>
									</CardHeader>
									<CardContent className="text-xs">
										<p className="text-muted-foreground font-sans leading-relaxed whitespace-pre-wrap">
											{assessmentResults.final_report}
										</p>
									</CardContent>
								</Card>
							)}

							{/* Findings List Grouped by Severity */}
							<div className="space-y-4">
								<h3 className="text-base font-semibold tracking-tight flex items-center gap-2">
									<ShieldAlert className="h-5 w-5 text-rose-500" />
									Confirmed Security Findings ({assessmentResults.findings.length})
								</h3>

								{assessmentResults.findings.length === 0 ? (
									<Card className="border-muted bg-muted/10 p-6 text-center text-xs text-muted-foreground">
										{assessmentResults.status === "running" || assessmentResults.status === "starting"
											? "Autonomous scan is actively probing target. Real findings will appear here as discovered."
											: "No security vulnerabilities detected during this assessment run."}
									</Card>
								) : (
									<div className="space-y-3">
									{assessmentResults.findings.map((f) => {
										const getSeverityColor = (sev: string) => {
											switch (sev) {
												case "Critical":
													return "border-rose-500/40 bg-rose-500/[0.03]";
												case "High":
													return "border-orange-500/40 bg-orange-500/[0.03]";
												case "Medium":
													return "border-amber-500/40 bg-amber-500/[0.03]";
												case "Low":
													return "border-blue-500/40 bg-blue-500/[0.03]";
												default:
													return "border-muted bg-muted/20";
											}
										};

										const getSeverityBadge = (sev: string) => {
											switch (sev) {
												case "Critical":
													return <Badge className="bg-rose-600 text-white font-bold">{sev}</Badge>;
												case "High":
													return <Badge className="bg-orange-600 text-white font-bold">{sev}</Badge>;
												case "Medium":
													return <Badge className="bg-amber-600 text-white font-bold">{sev}</Badge>;
												case "Low":
													return <Badge className="bg-blue-600 text-white font-bold">{sev}</Badge>;
												default:
													return <Badge variant="secondary">{sev}</Badge>;
											}
										};

										return (
											<Card key={f.id} className={`${getSeverityColor(f.severity)} border transition-all`}>
												<CardHeader className="pb-3">
													<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
														<div className="flex items-center gap-2.5">
															{getSeverityBadge(f.severity)}
															<span className="font-mono text-xs text-muted-foreground">{f.id}</span>
															<h4 className="font-semibold text-sm">{f.title}</h4>
														</div>
														<div className="flex items-center gap-2">
															<Badge variant="outline" className="text-xs font-mono">{f.cwe}</Badge>
															<Badge className="bg-emerald-600 text-white text-xs">{f.verification}</Badge>
														</div>
													</div>
													<div className="text-xs text-muted-foreground font-mono mt-1">
														Endpoint: <span className="text-foreground font-semibold">{f.affected_url}</span>
														{f.parameter && (
															<span className="ml-2">• Param: <span className="font-semibold text-foreground">{f.parameter}</span></span>
														)}
													</div>
												</CardHeader>
												<CardContent className="space-y-2.5 text-xs">
													<div className="p-3 rounded-md bg-muted/30 border">
														<div className="font-semibold text-foreground mb-1">Observed Technical Evidence</div>
														<p className="font-mono text-[11px] text-muted-foreground leading-relaxed whitespace-pre-wrap">
															{f.evidence}
														</p>
													</div>

													<div className="p-3 rounded-md bg-emerald-500/[0.05] border border-emerald-500/20">
														<div className="font-semibold text-emerald-800 dark:text-emerald-300 mb-1">
															Remediation Recommendation ({f.remediation_time})
														</div>
														<p className="text-muted-foreground">{f.recommendation}</p>
													</div>
												</CardContent>
											</Card>
										);
									})}
								</div>
								)}
							</div>

							{/* ScopeEnforcer Intercepted Out-of-Scope Requests */}
							<Card className="border-amber-500/30">
								<CardHeader>
									<div className="flex items-center gap-2">
										<Ban className="h-5 w-5 text-amber-500" />
										<CardTitle className="text-base">ScopeEnforcer Interception Log</CardTitle>
									</div>
									<CardDescription>
										Autonomous pentesting requests blocked before reaching unauthorized targets or excluded paths
									</CardDescription>
								</CardHeader>
								<CardContent>
									<Table>
										<TableHeader>
											<TableRow>
												<TableHead>Timestamp</TableHead>
												<TableHead>Target URL</TableHead>
												<TableHead>Interception Policy Reason</TableHead>
											</TableRow>
										</TableHeader>
										<TableBody>
											{assessmentResults.blocked_requests.map((b, idx) => (
												<TableRow key={idx}>
													<TableCell className="font-mono text-xs text-muted-foreground">
														{new Date(b.timestamp).toLocaleTimeString()}
													</TableCell>
													<TableCell className="font-mono text-xs font-semibold text-rose-600">
														{b.target_url}
													</TableCell>
													<TableCell className="text-xs text-muted-foreground">{b.reason}</TableCell>
												</TableRow>
											))}
										</TableBody>
									</Table>
								</CardContent>
							</Card>
						</>
					) : (
						<div className="text-center py-12 text-muted-foreground text-sm">
							No completed assessment results available. Launch a pentest run against a practice lab or approved grant.
						</div>
					)}
				</TabsContent>

				{/* TAB 5: AUDIT TRAIL */}
				<TabsContent value="audit" className="space-y-6 mt-6">
					<Card>
						<CardHeader>
							<div className="flex items-center justify-between">
								<div>
									<CardTitle className="text-base">Structured Security Audit Trail</CardTitle>
									<CardDescription>
										Authoritative chronological records of lab provisioning, grant minting, and access violations
									</CardDescription>
								</div>
								<Badge variant="outline" className="text-xs text-emerald-600 font-mono">
									ZERO_SECRETS_LOGGED
								</Badge>
							</div>
						</CardHeader>
						<CardContent>
							{auditEvents && auditEvents.length > 0 ? (
								<Table>
									<TableHeader>
										<TableRow>
											<TableHead>Timestamp</TableHead>
											<TableHead>Event Type</TableHead>
											<TableHead>User ID</TableHead>
											<TableHead>Org ID</TableHead>
											<TableHead>Audit Details</TableHead>
										</TableRow>
									</TableHeader>
									<TableBody>
										{auditEvents.slice(-25).reverse().map((ev, idx) => (
											<TableRow key={idx}>
												<TableCell className="font-mono text-xs text-muted-foreground">
													{new Date(ev.timestamp).toLocaleTimeString()}
												</TableCell>
												<TableCell>
													<Badge
														variant={
															ev.event_type.includes("FAILURE") || ev.event_type.includes("VIOLATION")
																? "destructive"
																: "outline"
														}
														className="text-[11px] font-mono font-semibold"
													>
														{ev.event_type}
													</Badge>
												</TableCell>
												<TableCell className="font-mono text-xs">{ev.user_id}</TableCell>
												<TableCell className="font-mono text-xs text-muted-foreground">{ev.org_id}</TableCell>
												<TableCell className="text-xs text-muted-foreground font-mono">{ev.details}</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							) : (
								<div className="text-center py-8 text-muted-foreground text-sm">
									No audit events recorded yet.
								</div>
							)}
						</CardContent>
					</Card>
				</TabsContent>
			</Tabs>
		</div>
	);
}
