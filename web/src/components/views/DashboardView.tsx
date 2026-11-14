import React from "react";
import {
	Server,
	Globe,
	Bug,
	Shield,
	PlusCircle,
	Activity,
	Clock,
	CheckCircle2,
	AlertTriangle,
	Play,
	ArrowRight,
	FileText,
	ShieldCheck,
	Layers,
	ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
	LabSession,
	AuthorizationGrant,
	AssessmentResultsResponse,
	AssessmentStatusResponse,
	AuditEvent,
	SecurityFinding,
} from "@/store";
import { TargetDisplay } from "@/components/common/TargetDisplay";
import { classifyFinding } from "@/lib/telemetry";

interface DashboardViewProps {
	managedLabs?: LabSession[];
	externalGrants?: AuthorizationGrant[];
	assessmentResults?: AssessmentResultsResponse;
	liveStatus?: AssessmentStatusResponse;
	auditEvents?: AuditEvent[];
	onNavigate: (view: string, subTab?: string) => void;
	onStartAssessment: (grantId?: string) => void;
	onStopLab: (labId: string) => void;
	isStoppingLab: boolean;
	copiedTarget: boolean;
	onCopy: (text: string) => void;
	renderStatusBadge: (status: string) => React.ReactNode;
}

export function DashboardView({
	managedLabs,
	externalGrants,
	assessmentResults,
	liveStatus,
	auditEvents,
	onNavigate,
	onStartAssessment,
	onStopLab,
	isStoppingLab,
	copiedTarget,
	onCopy,
	renderStatusBadge,
}: DashboardViewProps) {
	const activeLab = managedLabs?.find((l) => l.status === "running");
	const isAssessmentRunning =
		liveStatus?.status === "running" ||
		liveStatus?.status === "starting" ||
		liveStatus?.status === "active";

	const currentRunId = liveStatus?.run_id || assessmentResults?.run_id || "";
	const currentTarget = liveStatus?.target || assessmentResults?.target || "";
	const durationSeconds = assessmentResults?.duration_seconds ?? liveStatus?.duration_seconds ?? 0;

	// Authoritative canonical finding calculations
	const allFindings = assessmentResults?.findings || [];
	const confirmedFindings = allFindings.filter((f) => classifyFinding(f, currentRunId) === "Confirmed");
	const potentialFindings = allFindings.filter((f) => classifyFinding(f, currentRunId) === "Potential");
	const inconclusiveFindings = allFindings.filter((f) => classifyFinding(f, currentRunId) === "Inconclusive");

	const criticalCount = confirmedFindings.filter((f) => f.severity?.toLowerCase() === "critical").length;
	const highCount = confirmedFindings.filter((f) => f.severity?.toLowerCase() === "high").length;
	const mediumCount = confirmedFindings.filter((f) => f.severity?.toLowerCase() === "medium").length;
	const lowCount = confirmedFindings.filter((f) => f.severity?.toLowerCase() === "low").length;

	const activeGrants =
		externalGrants?.filter((g) => g.approval_status === "approved" && !g.is_revoked) || [];

	const severityBadge = (sev: string) => {
		switch (sev?.toLowerCase()) {
			case "critical":
				return <Badge className="bg-rose-600 text-white border-0 text-[10px] font-bold">CRITICAL</Badge>;
			case "high":
				return <Badge className="bg-orange-600 text-white border-0 text-[10px] font-bold">HIGH</Badge>;
			case "medium":
				return <Badge className="bg-amber-600 text-white border-0 text-[10px] font-bold">MEDIUM</Badge>;
			default:
				return <Badge className="bg-blue-600 text-white border-0 text-[10px] font-bold">LOW</Badge>;
		}
	};

	return (
		<div className="space-y-6">
			{/* Top Header */}
			<div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-2 border-b border-border/40">
				<div>
					<h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
						<Shield className="h-6 w-6 text-primary" />
						Security Operations Overview
					</h1>
					<p className="text-xs text-muted-foreground mt-0.5">
						On-demand autonomous penetration testing, deterministic scope control, and verified exploit proofs.
					</p>
				</div>
				<div className="flex items-center gap-2.5">
					{isAssessmentRunning && (
						<Button
							variant="outline"
							size="sm"
							onClick={() => onNavigate("live-assessment")}
							className="gap-2 border-emerald-500/40 text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 text-xs font-semibold"
						>
							<Activity className="h-3.5 w-3.5 animate-pulse" />
							Live Assessment
						</Button>
					)}
					<Button
						onClick={() => onNavigate("welcome")}
						className="gap-2 text-xs bg-primary text-primary-foreground hover:bg-primary/90 font-semibold shadow-sm"
					>
						<PlusCircle className="h-4 w-4" />
						New Assessment
					</Button>
				</div>
			</div>

			{/* Exactly 4 Clean Summary Metric Cards */}
			<div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
				{/* 1. Configured Applications */}
				<Card className="border-border/60 bg-card hover:border-primary/40 transition-colors shadow-sm">
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
							Configured Applications
						</CardTitle>
						<Server className="h-4 w-4 text-primary" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-extrabold text-foreground">
							{(activeLab ? 1 : 0) + activeGrants.length}
						</div>
						<p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1.5 truncate">
							<span className={activeLab ? "text-emerald-400 font-semibold" : ""}>
								{activeLab ? "1 Practice Lab Active" : "Practice Lab Offline"}
							</span>
							<span>•</span>
							<span>{activeGrants.length} External Grant(s)</span>
						</p>
					</CardContent>
				</Card>

				{/* 2. Running Assessments */}
				<Card className="border-border/60 bg-card hover:border-primary/40 transition-colors shadow-sm">
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
							Running Assessments
						</CardTitle>
						<Activity className="h-4 w-4 text-emerald-400" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-extrabold text-foreground">
							{isAssessmentRunning ? 1 : 0}
						</div>
						<p className="text-[11px] text-muted-foreground mt-1 truncate">
							{isAssessmentRunning
								? `Active Run: ${currentRunId.substring(0, 16)}...`
								: "No active assessments in progress"}
						</p>
					</CardContent>
				</Card>

				{/* 3. Confirmed Vulnerabilities */}
				<Card className="border-border/60 bg-card hover:border-primary/40 transition-colors shadow-sm">
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
							Confirmed Vulnerabilities
						</CardTitle>
						<Bug className="h-4 w-4 text-rose-400" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-extrabold text-rose-400">
							{confirmedFindings.length}
						</div>
						<p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1.5">
							<span className="font-semibold text-rose-400">{criticalCount + highCount} High/Crit</span>
							<span>•</span>
							<span>{mediumCount} Med</span>
							<span>•</span>
							<span>{lowCount} Low</span>
						</p>
					</CardContent>
				</Card>

				{/* 4. Latest Assessment Status */}
				<Card className="border-border/60 bg-card hover:border-primary/40 transition-colors shadow-sm">
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
							Latest Assessment Status
						</CardTitle>
						<Clock className="h-4 w-4 text-primary" />
					</CardHeader>
					<CardContent>
						<div className="flex items-center gap-2">
							{isAssessmentRunning ? (
								<Badge className="bg-amber-500/20 text-amber-300 border-amber-500/30 text-xs font-bold">
									RUNNING
								</Badge>
							) : assessmentResults?.status === "completed" ? (
								<Badge className="bg-emerald-600/20 text-emerald-400 border-emerald-500/30 text-xs font-bold">
									COMPLETED
								</Badge>
							) : assessmentResults?.status === "failed" ? (
								<Badge className="bg-rose-500/20 text-rose-300 border-rose-500/30 text-xs font-bold">
									FAILED
								</Badge>
							) : (
								<Badge variant="outline" className="text-xs font-medium">
									IDLE
								</Badge>
							)}
						</div>
						<p className="text-[11px] text-muted-foreground mt-1 truncate">
							{assessmentResults?.run_id
								? `Duration: ${durationSeconds}s • ${assessmentResults.tools_executed?.length || 0} tools executed`
								: "Ready for deployment"}
						</p>
					</CardContent>
				</Card>
			</div>

			{/* Recent Assessments Section */}
			<Card className="border-border/60 bg-card shadow-sm">
				<CardHeader className="flex flex-row items-center justify-between pb-3">
					<div>
						<CardTitle className="text-sm font-bold text-foreground">Recent Assessments</CardTitle>
						<CardDescription className="text-xs">
							Autonomous multi-agent execution records with verified evidence.
						</CardDescription>
					</div>
					<Button
						variant="ghost"
						size="sm"
						onClick={() => onNavigate("findings")}
						className="text-xs text-primary hover:text-primary/90 gap-1"
					>
						View All Results
						<ChevronRight className="h-3.5 w-3.5" />
					</Button>
				</CardHeader>
				<CardContent>
					{assessmentResults?.run_id ? (
						<div className="border border-border/60 rounded-xl overflow-hidden">
							<Table>
								<TableHeader className="bg-muted/30">
									<TableRow className="border-border/60">
										<TableHead className="text-[11px] font-bold">Run ID</TableHead>
										<TableHead className="text-[11px] font-bold">Target System</TableHead>
										<TableHead className="text-[11px] font-bold text-center">Duration</TableHead>
										<TableHead className="text-[11px] font-bold text-center">Tools / Probes</TableHead>
										<TableHead className="text-[11px] font-bold text-center">Findings</TableHead>
										<TableHead className="text-[11px] font-bold text-center">Status</TableHead>
										<TableHead className="text-[11px] font-bold text-right">Action</TableHead>
									</TableRow>
								</TableHeader>
								<TableBody>
									<TableRow className="border-border/40">
										<TableCell className="font-mono text-xs font-bold text-foreground">
											{assessmentResults.run_id.substring(0, 16)}...
										</TableCell>
										<TableCell className="text-xs">
											<div className="font-semibold text-foreground">
												{assessmentResults.target?.includes("practice-lab") || assessmentResults.target?.includes("5000")
													? "OWASP Juice Shop (Practice Lab)"
													: assessmentResults.target}
											</div>
											<div className="text-[10px] text-muted-foreground font-mono">
												{assessmentResults.target}
											</div>
										</TableCell>
										<TableCell className="text-xs text-center font-mono">
											{durationSeconds}s
										</TableCell>
										<TableCell className="text-xs text-center font-mono">
											{assessmentResults.tools_executed?.length || 0} tools ({assessmentResults.tools_executed?.reduce((s, t) => s + (t.invocations || 1), 0) || 0} probes)
										</TableCell>
										<TableCell className="text-xs text-center">
											<span className="font-bold text-rose-400">
												{confirmedFindings.length} confirmed
											</span>
											{(potentialFindings.length > 0 || inconclusiveFindings.length > 0) && (
												<div className="text-[10px] text-muted-foreground">
													{potentialFindings.length > 0 ? `${potentialFindings.length} pot ` : ""}{inconclusiveFindings.length > 0 ? `${inconclusiveFindings.length} inconv` : ""}
												</div>
											)}
										</TableCell>
										<TableCell className="text-center">
											{renderStatusBadge(assessmentResults.status || "completed")}
										</TableCell>
										<TableCell className="text-right">
											<Button
												size="sm"
												variant="outline"
												onClick={() => onNavigate("findings")}
												className="text-xs font-semibold gap-1 py-1"
											>
												<FileText className="h-3 w-3" />
												View Findings
											</Button>
										</TableCell>
									</TableRow>
								</TableBody>
							</Table>
						</div>
					) : (
						<div className="flex flex-col items-center justify-center p-8 text-center space-y-3 bg-muted/20 rounded-xl border border-border/40">
							<div className="p-3 rounded-full bg-primary/10 text-primary">
								<Layers className="h-6 w-6" />
							</div>
							<div>
								<h3 className="text-sm font-bold text-foreground">No assessments recorded yet</h3>
								<p className="text-xs text-muted-foreground max-w-sm mt-0.5">
									Launch an autonomous penetration test against the practice lab to test vulnerabilities safely.
								</p>
							</div>
							<Button
								size="sm"
								onClick={() => onNavigate("welcome")}
								className="gap-2 text-xs font-semibold bg-primary text-primary-foreground"
							>
								<PlusCircle className="h-3.5 w-3.5" />
								Start First Assessment
							</Button>
						</div>
					)}
				</CardContent>
			</Card>

			{/* Recent Security Findings Section */}
			<Card className="border-border/60 bg-card shadow-sm">
				<CardHeader className="flex flex-row items-center justify-between pb-3">
					<div>
						<CardTitle className="text-sm font-bold text-foreground">Recent Security Findings</CardTitle>
						<CardDescription className="text-xs">
							Independently confirmed vulnerabilities backed by negative controls.
						</CardDescription>
					</div>
					{confirmedFindings.length > 0 && (
						<Button
							variant="ghost"
							size="sm"
							onClick={() => onNavigate("findings")}
							className="text-xs text-primary hover:text-primary/90 gap-1"
						>
							View Full Ledger ({confirmedFindings.length})
							<ChevronRight className="h-3.5 w-3.5" />
						</Button>
					)}
				</CardHeader>
				<CardContent>
					{confirmedFindings.length > 0 ? (
						<div className="border border-border/60 rounded-xl overflow-hidden">
							<Table>
								<TableHeader className="bg-muted/30">
									<TableRow className="border-border/60">
										<TableHead className="text-[11px] font-bold">Severity</TableHead>
										<TableHead className="text-[11px] font-bold">Vulnerability Title</TableHead>
										<TableHead className="text-[11px] font-bold">Affected URL & Parameter</TableHead>
										<TableHead className="text-[11px] font-bold">Category / CWE</TableHead>
										<TableHead className="text-[11px] font-bold text-center">Confidence</TableHead>
										<TableHead className="text-[11px] font-bold text-right">Action</TableHead>
									</TableRow>
								</TableHeader>
								<TableBody>
									{confirmedFindings.map((f, idx) => (
										<TableRow key={f.id || idx} className="border-border/40 hover:bg-muted/40 transition-colors">
											<TableCell>{severityBadge(f.severity)}</TableCell>
											<TableCell>
												<div className="font-semibold text-xs text-foreground">{f.title}</div>
												{f.parameter && (
													<div className="text-[10px] text-muted-foreground font-mono">
														param: {f.parameter}
													</div>
												)}
											</TableCell>
											<TableCell className="font-mono text-xs text-muted-foreground">
												{f.affected_url}
											</TableCell>
											<TableCell>
												<div className="text-xs font-medium text-foreground">{f.cwe || "CWE-639"}</div>
												<div className="text-[10px] text-muted-foreground">{f.category || "Broken Access Control"}</div>
											</TableCell>
											<TableCell className="text-center">
												<Badge className="bg-emerald-600/20 text-emerald-400 border-emerald-500/30 text-[10px]">
													{f.confidence || "High"}
												</Badge>
											</TableCell>
											<TableCell className="text-right">
												<Button
													size="sm"
													variant="outline"
													onClick={() => onNavigate("findings")}
													className="text-xs font-semibold gap-1 py-1"
												>
													<FileText className="h-3 w-3" />
													Inspect Proof
												</Button>
											</TableCell>
										</TableRow>
									))}
								</TableBody>
							</Table>
						</div>
					) : (
						<div className="flex flex-col items-center justify-center p-8 text-center space-y-3 bg-muted/20 rounded-xl border border-border/40">
							<div className="p-3 rounded-full bg-emerald-500/10 text-emerald-400">
								<ShieldCheck className="h-6 w-6" />
							</div>
							<div>
								<h3 className="text-sm font-bold text-foreground">Zero confirmed vulnerabilities</h3>
								<p className="text-xs text-muted-foreground max-w-sm mt-0.5">
									No confirmed security findings recorded in the active ledger. Run an assessment to probe for vulnerabilities.
								</p>
							</div>
						</div>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
