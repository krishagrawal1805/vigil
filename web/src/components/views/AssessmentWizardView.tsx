import React, { useState } from "react";
import {
	Server,
	Globe,
	Shield,
	Lock,
	CheckCircle2,
	AlertTriangle,
	XCircle,
	ArrowRight,
	ArrowLeft,
	Play,
	KeyRound,
	Layers,
	Eye,
	EyeOff,
	Zap,
	Search,
	FileText,
	RotateCcw,
	Activity,
	Terminal,
	Check,
	ExternalLink,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
	LabSession,
	AuthorizationGrant,
	RegisterExternalRequest,
} from "@/store";

interface AssessmentWizardViewProps {
	managedLabs?: LabSession[];
	externalGrants?: AuthorizationGrant[];
	onStartLab: () => Promise<void>;
	isStartingLab: boolean;
	onStartAssessment: (grantId?: string, targetUrl?: string) => Promise<void>;
	isStartingRun: boolean;
	onRegisterExternal: (payload: RegisterExternalRequest) => Promise<void>;
	isRegisteringExt: boolean;
	onNavigate: (view: string) => void;
	initialTemplate?: "comprehensive" | "enumeration" | "retest";
	initialTargetType?: "managed" | "external";
}

type WizardStep =
	| "template"
	| "target"
	| "auth"
	| "scope"
	| "pre-flight"
	| "review-launch";

export function AssessmentWizardView({
	managedLabs,
	externalGrants,
	onStartLab,
	isStartingLab,
	onStartAssessment,
	isStartingRun,
	onRegisterExternal,
	isRegisteringExt,
	onNavigate,
	initialTemplate = "comprehensive",
	initialTargetType = "managed",
}: AssessmentWizardViewProps) {
	// Step 1: Template Selection (NodeZero inspired)
	const [step, setStep] = useState<WizardStep>("template");
	const [assessmentTemplate, setAssessmentTemplate] = useState<"comprehensive" | "enumeration" | "retest">(initialTemplate);

	// Step 2: Target Selection
	const [targetType, setTargetType] = useState<"managed" | "external">(initialTargetType);
	const [appName, setAppName] = useState<string>("OWASP Juice Shop / Practice Lab");
	const [targetUrl, setTargetUrl] = useState<string>("http://127.0.0.1:5000");
	const [extHost, setExtHost] = useState<string>("");
	const [extPort, setExtPort] = useState<number>(443);

	// Step 3: Target Authentication Configuration
	const [authMethod, setAuthMethod] = useState<"none" | "credentials" | "bearer" | "cookie" | "apikey">("credentials");
	const [targetUsername, setTargetUsername] = useState<string>("admin@juice-sh.op");
	const [targetPassword, setTargetPassword] = useState<string>("admin123");
	const [bearerToken, setBearerToken] = useState<string>("");
	const [sessionCookie, setSessionCookie] = useState<string>("");
	const [apiKey, setApiKey] = useState<string>("");
	const [authTestStatus, setAuthTestStatus] = useState<"not_configured" | "pending" | "success" | "failed">("not_configured");
	const [showSecrets, setShowSecrets] = useState<boolean>(false);

	// Step 4: Scope Configuration
	const [allowedPaths, setAllowedPaths] = useState<string>("/rest/, /api/, /public/");
	const [blockedPaths, setBlockedPaths] = useState<string>("/admin/, /private/, /payments/");
	const [allowedMethods, setAllowedMethods] = useState<string>("GET, POST, PUT, DELETE");

	// Active lab & grant check
	const activeLab = managedLabs?.find((l) => l.status === "running");
	const approvedExternalGrant = externalGrants?.find((g) => g.approval_status === "approved" && !g.is_revoked);

	// Template switcher defaults
	const handleSelectTemplate = (tmpl: "comprehensive" | "enumeration" | "retest") => {
		setAssessmentTemplate(tmpl);
		if (tmpl === "comprehensive") {
			setAllowedPaths("/rest/, /api/, /public/");
			setBlockedPaths("/admin/, /private/, /payments/");
			setAllowedMethods("GET, POST, PUT, DELETE");
		} else if (tmpl === "enumeration") {
			setAllowedPaths("/rest/, /api/, /public/");
			setBlockedPaths("/admin/, /private/");
			setAllowedMethods("GET, HEAD, OPTIONS");
		} else if (tmpl === "retest") {
			setAllowedPaths("/rest/basket/, /rest/admin/");
			setBlockedPaths("/admin/logout");
			setAllowedMethods("GET, POST");
		}
	};

	// Handle Auth Test
	const handleTestAuth = () => {
		setAuthTestStatus("pending");
		setTimeout(() => {
			if (targetType === "managed") {
				setAuthTestStatus("success");
			} else {
				if (authMethod === "credentials" && targetUsername && targetPassword) {
					setAuthTestStatus("success");
				} else if (authMethod === "bearer" && bearerToken) {
					setAuthTestStatus("success");
				} else if (authMethod === "none") {
					setAuthTestStatus("not_configured");
				} else {
					setAuthTestStatus("failed");
				}
			}
		}, 1000);
	};

	// Determine Pre-flight conditions
	const isConnected = targetType === "managed" ? !!activeLab : !!approvedExternalGrant;
	const isVerified = authMethod === "none" || authTestStatus === "success";
	const isScopingComplete = allowedPaths.trim().length > 0;
	const isGrantValid = targetType === "managed" ? !!activeLab?.grant_id : !!approvedExternalGrant?.grant_id;
	const canProceedToLaunch = isConnected && isGrantValid && isScopingComplete;

	const handleLaunch = async () => {
		if (targetType === "managed") {
			await onStartAssessment(activeLab?.grant_id, activeLab?.target_url || "http://platform-practice-lab:3000");
		} else {
			if (!approvedExternalGrant) {
				alert("Please approve an external authorization grant before launching an external assessment.");
				return;
			}
			await onStartAssessment(approvedExternalGrant.grant_id, `https://${approvedExternalGrant.authorized_host}:${approvedExternalGrant.authorized_port}`);
		}
	};

	const stepsOrder: { id: WizardStep; label: string; num: number }[] = [
		{ id: "template", label: "Template", num: 1 },
		{ id: "target", label: "Target", num: 2 },
		{ id: "auth", label: "Authentication", num: 3 },
		{ id: "scope", label: "Scope Bounds", num: 4 },
		{ id: "pre-flight", label: "Pre-Flight", num: 5 },
		{ id: "review-launch", label: "Launch", num: 6 },
	];

	const currentStepIndex = stepsOrder.findIndex((s) => s.id === step);

	return (
		<div className="max-w-4xl mx-auto space-y-6">
			{/* Wizard Header */}
			<div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-2 border-b border-border/40">
				<div>
					<h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
						<Shield className="h-6 w-6 text-primary" />
						New Security Assessment
					</h1>
					<p className="text-xs text-muted-foreground mt-0.5">
						Guided 6-step assessment workflow with deterministic ScopeEnforcer bounds and verified proofs.
					</p>
				</div>
				<Badge variant="outline" className="text-xs px-2.5 py-1 font-mono">
					Step {currentStepIndex + 1} of 6: {stepsOrder[currentStepIndex].label}
				</Badge>
			</div>

			{/* Clean Horizontal Step Indicator */}
			<div className="hidden sm:flex items-center justify-between px-2 py-3 bg-card border border-border/60 rounded-xl shadow-sm">
				{stepsOrder.map((s, idx) => {
					const isPast = idx < currentStepIndex;
					const isCurrent = idx === currentStepIndex;
					return (
						<div key={s.id} className="flex items-center gap-2 flex-1 last:flex-none">
							<div
								className={`
									flex items-center justify-center h-7 w-7 rounded-full text-xs font-bold transition-all
									${isCurrent ? "bg-primary text-primary-foreground shadow" : isPast ? "bg-emerald-600 text-white" : "bg-muted text-muted-foreground"}
								`}
							>
								{isPast ? <Check className="h-4 w-4" /> : s.num}
							</div>
							<span className={`text-xs font-medium ${isCurrent ? "text-foreground font-semibold" : isPast ? "text-muted-foreground" : "text-muted-foreground/60"}`}>
								{s.label}
							</span>
							{idx < stepsOrder.length - 1 && (
								<div className={`h-0.5 flex-1 mx-2 ${idx < currentStepIndex ? "bg-emerald-600/40" : "bg-border/60"}`} />
							)}
						</div>
					);
				})}
			</div>

			{/* ================= STEP 1: CHOOSE ASSESSMENT TEMPLATE ================= */}
			{step === "template" && (
				<Card className="border-border/60 bg-card shadow-sm">
					<CardHeader>
						<CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
							<Layers className="h-5 w-5 text-primary" />
							Select Assessment Template
						</CardTitle>
						<CardDescription className="text-xs">
							Choose an assessment template tailored to your operational goal. Sensible defaults are automatically applied.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
							{/* Template 1: Comprehensive Web Assessment */}
							<div
								onClick={() => handleSelectTemplate("comprehensive")}
								className={`
									p-5 rounded-xl border-2 cursor-pointer transition-all flex flex-col justify-between
									${assessmentTemplate === "comprehensive"
										? "border-primary bg-primary/5 shadow-sm"
										: "border-border/60 bg-card hover:border-primary/40"
									}
								`}
							>
								<div className="space-y-3">
									<div className="flex items-center justify-between">
										<div className="h-10 w-10 rounded-lg bg-primary/10 border border-primary/20 text-primary flex items-center justify-center">
											<Shield className="h-5 w-5" />
										</div>
										<Badge className="bg-primary/20 text-primary border-primary/30 text-[10px]">
											Deep Inspection
										</Badge>
									</div>
									<div>
										<h3 className="text-sm font-bold text-foreground">
											Comprehensive Web Assessment
										</h3>
										<p className="text-xs text-muted-foreground mt-1 leading-relaxed">
											Autonomous multi-agent penetration test probing input injection, broken access control (BOLA/IDOR), cryptographic flaws (JWT), and cross-site scripting (XSS).
										</p>
									</div>
									<div className="space-y-1.5 text-[11px] text-muted-foreground border-t border-border/40 pt-2.5">
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Attack surface discovery & mapping</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>BOLA/IDOR boundary validation</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>JWT signature & algorithm testing</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Reflected & DOM XSS validation</span>
										</div>
									</div>
								</div>
								<div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between">
									<span className="text-[10px] text-muted-foreground">Methods: GET, POST, PUT, DELETE</span>
									{assessmentTemplate === "comprehensive" && (
										<Badge className="bg-primary text-primary-foreground text-[10px]">SELECTED</Badge>
									)}
								</div>
							</div>

							{/* Template 2: Surface Enumeration */}
							<div
								onClick={() => handleSelectTemplate("enumeration")}
								className={`
									p-5 rounded-xl border-2 cursor-pointer transition-all flex flex-col justify-between
									${assessmentTemplate === "enumeration"
										? "border-primary bg-primary/5 shadow-sm"
										: "border-border/60 bg-card hover:border-primary/40"
									}
								`}
							>
								<div className="space-y-3">
									<div className="flex items-center justify-between">
										<div className="h-10 w-10 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center">
											<Search className="h-5 w-5" />
										</div>
										<Badge variant="outline" className="text-blue-400 border-blue-500/30 text-[10px]">
											Passive & Safe
										</Badge>
									</div>
									<div>
										<h3 className="text-sm font-bold text-foreground">
											Surface Enumeration
										</h3>
										<p className="text-xs text-muted-foreground mt-1 leading-relaxed">
											Lightweight attack surface discovery mapping exposed REST API routes, documentation endpoints, and potential ingress points without destructive payload execution.
										</p>
									</div>
									<div className="space-y-1.5 text-[11px] text-muted-foreground border-t border-border/40 pt-2.5">
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>OpenAPI / Swagger endpoint enumeration</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Header & security policy analysis</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Safe, non-destructive GET requests</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Zero exploit transmission</span>
										</div>
									</div>
								</div>
								<div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between">
									<span className="text-[10px] text-muted-foreground">Methods: GET, HEAD, OPTIONS</span>
									{assessmentTemplate === "enumeration" && (
										<Badge className="bg-primary text-primary-foreground text-[10px]">SELECTED</Badge>
									)}
								</div>
							</div>

							{/* Template 3: Targeted Retest */}
							<div
								onClick={() => handleSelectTemplate("retest")}
								className={`
									p-5 rounded-xl border-2 cursor-pointer transition-all flex flex-col justify-between
									${assessmentTemplate === "retest"
										? "border-primary bg-primary/5 shadow-sm"
										: "border-border/60 bg-card hover:border-primary/40"
									}
								`}
							>
								<div className="space-y-3">
									<div className="flex items-center justify-between">
										<div className="h-10 w-10 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center">
											<RotateCcw className="h-5 w-5" />
										</div>
										<Badge variant="outline" className="text-purple-400 border-purple-500/30 text-[10px]">
											Patch Verification
										</Badge>
									</div>
									<div>
										<h3 className="text-sm font-bold text-foreground">
											Targeted Retest
										</h3>
										<p className="text-xs text-muted-foreground mt-1 leading-relaxed">
											Focused security re-evaluation targeting previously confirmed vulnerabilities to verify patch deployment and prevent security regressions.
										</p>
									</div>
									<div className="space-y-1.5 text-[11px] text-muted-foreground border-t border-border/40 pt-2.5">
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Isolated single-endpoint verification</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Reproduction proof comparison</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Cryptographically signed audit record</span>
										</div>
										<div className="flex items-center gap-1.5">
											<CheckCircle2 className="h-3 w-3 text-emerald-400" />
											<span>Automated regression check</span>
										</div>
									</div>
								</div>
								<div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between">
									<span className="text-[10px] text-muted-foreground">Methods: Targeted routes</span>
									{assessmentTemplate === "retest" && (
										<Badge className="bg-primary text-primary-foreground text-[10px]">SELECTED</Badge>
									)}
								</div>
							</div>
						</div>
					</CardContent>
					<CardFooter className="flex justify-end pt-4 border-t border-border/40">
						<Button
							onClick={() => setStep("target")}
							className="gap-2 text-xs font-semibold"
						>
							Continue to Target Selection
							<ArrowRight className="h-4 w-4" />
						</Button>
					</CardFooter>
				</Card>
			)}

			{/* ================= STEP 2: SELECT OR CONFIGURE TARGET ================= */}
			{step === "target" && (
				<Card className="border-border/60 bg-card shadow-sm">
					<CardHeader>
						<CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
							<Server className="h-5 w-5 text-primary" />
							Select or Configure Target
						</CardTitle>
						<CardDescription className="text-xs">
							Choose whether to test the managed practice lab or an authorized external web application.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-5">
						<div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
							{/* Option A: Managed Practice Lab */}
							<div
								onClick={() => {
									setTargetType("managed");
									setAppName("OWASP Juice Shop / Practice Lab");
									setTargetUrl("http://127.0.0.1:5000");
								}}
								className={`
									p-4 rounded-xl border-2 cursor-pointer transition-all flex flex-col justify-between
									${targetType === "managed" ? "border-emerald-500 bg-emerald-500/5 shadow-sm" : "border-border/60 bg-card hover:border-border"}
								`}
							>
								<div className="space-y-2">
									<div className="flex items-center justify-between">
										<div className="flex items-center gap-2">
											<Server className="h-4 w-4 text-emerald-400" />
											<span className="text-sm font-bold text-foreground">Managed Practice Lab</span>
										</div>
										<Badge className="bg-emerald-600 text-white text-[10px]">SANDBOX</Badge>
									</div>
									<p className="text-xs text-muted-foreground">
										Pre-deployed OWASP Juice Shop on port 5000 with loopback binding and deterministic ScopeEnforcer bounds.
									</p>
								</div>
								<div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between text-xs">
									<span className="text-muted-foreground font-mono">http://127.0.0.1:5000</span>
									{activeLab ? (
										<Badge className="bg-emerald-600/20 text-emerald-400 border-emerald-500/30 text-[10px]">RUNNING</Badge>
									) : (
										<Badge variant="outline" className="text-amber-400 border-amber-500/30 text-[10px]">OFFLINE</Badge>
									)}
								</div>
							</div>

							{/* Option B: External Web Application */}
							<div
								onClick={() => {
									setTargetType("external");
									setAppName("Custom Web Application");
									setTargetUrl("");
								}}
								className={`
									p-4 rounded-xl border-2 cursor-pointer transition-all flex flex-col justify-between
									${targetType === "external" ? "border-primary bg-primary/5 shadow-sm" : "border-border/60 bg-card hover:border-border"}
								`}
							>
								<div className="space-y-2">
									<div className="flex items-center justify-between">
										<div className="flex items-center gap-2">
											<Globe className="h-4 w-4 text-blue-400" />
											<span className="text-sm font-bold text-foreground">External Web Application</span>
										</div>
										<Badge variant="outline" className="text-[10px]">ENTERPRISE</Badge>
									</div>
									<p className="text-xs text-muted-foreground">
										Assess an external domain or API with cryptographic DNS verification and two-person authorization.
									</p>
								</div>
								<div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between text-xs">
									<span className="text-muted-foreground">DNS TXT Challenge</span>
									{approvedExternalGrant ? (
										<Badge className="bg-emerald-600/20 text-emerald-400 border-emerald-500/30 text-[10px]">GRANT READY</Badge>
									) : (
										<Badge variant="outline" className="text-muted-foreground text-[10px]">REQUIRES GRANT</Badge>
									)}
								</div>
							</div>
						</div>

						{/* Details for selected target */}
						{targetType === "managed" ? (
							<div className="p-4 rounded-xl bg-card border border-border/60 space-y-3">
								<div className="flex items-center justify-between">
									<div>
										<h4 className="text-xs font-semibold text-foreground">Practice Lab Status</h4>
										<p className="text-[11px] text-muted-foreground">
											{activeLab
												? `Running with Grant ID: ${activeLab.grant_id || "Active"}. Ready for assessment.`
												: "Practice lab container is currently stopped. Launch it now to proceed."}
										</p>
									</div>
									{!activeLab && (
										<Button
											size="sm"
											onClick={onStartLab}
											disabled={isStartingLab}
											className="gap-2 text-xs bg-emerald-600 hover:bg-emerald-500 text-white font-semibold"
										>
											<Play className="h-3.5 w-3.5" />
											{isStartingLab ? "Starting..." : "Launch Practice Lab"}
										</Button>
									)}
								</div>
								{activeLab && (
									<div className="space-y-2 bg-muted/40 p-3 rounded-lg border border-border/40">
										<div className="grid grid-cols-2 gap-2 text-xs font-mono">
											<div><span className="text-muted-foreground">Browser URL:</span> {activeLab.browser_url || "http://127.0.0.1:5000"}</div>
											<div><span className="text-muted-foreground">Internal Agent:</span> {activeLab.target_url || "http://platform-practice-lab:3000"}</div>
										</div>
										<div className="pt-2 border-t border-border/40 flex items-center justify-between">
											<span className="text-[11px] text-emerald-400 font-medium">OWASP Juice Shop target running and reachable.</span>
											<a
												href={activeLab.browser_url || "http://127.0.0.1:5000"}
												target="_blank"
												rel="noreferrer"
												className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline font-semibold bg-primary/10 border border-primary/20 px-2.5 py-1 rounded-md"
											>
												Open Practice Application Target
												<ExternalLink className="h-3 w-3" />
											</a>
										</div>
									</div>
								)}
							</div>
						) : (
							<div className="p-4 rounded-xl bg-card border border-border/60 space-y-4">
								<div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
									<div className="space-y-1.5">
										<Label className="text-xs">Application Name</Label>
										<Input
											value={appName}
											onChange={(e) => setAppName(e.target.value)}
											placeholder="e.g. Staging Customer Portal"
											className="text-xs"
										/>
									</div>
									<div className="space-y-1.5">
										<Label className="text-xs">Target Host (FQDN or IP)</Label>
										<Input
											value={extHost}
											onChange={(e) => setExtHost(e.target.value)}
											placeholder="e.g. staging.example.com"
											className="text-xs font-mono"
										/>
									</div>
								</div>
								<div className="flex items-center justify-between pt-2">
									<p className="text-[11px] text-muted-foreground">
										{approvedExternalGrant
											? `Using approved grant: ${approvedExternalGrant.grant_id} (${approvedExternalGrant.authorized_host})`
											: "No approved external grant found. You will be guided through DNS verification in Step 5."}
									</p>
								</div>
							</div>
						)}
					</CardContent>
					<CardFooter className="flex justify-between pt-4 border-t border-border/40">
						<Button
							variant="outline"
							onClick={() => setStep("template")}
							className="gap-2 text-xs"
						>
							<ArrowLeft className="h-4 w-4" />
							Back
						</Button>
						<Button
							onClick={() => setStep("auth")}
							className="gap-2 text-xs font-semibold"
						>
							Continue to Authentication
							<ArrowRight className="h-4 w-4" />
						</Button>
					</CardFooter>
				</Card>
			)}

			{/* ================= STEP 3: CONFIGURE AUTHENTICATION ================= */}
			{step === "auth" && (
				<Card className="border-border/60 bg-card shadow-sm">
					<CardHeader>
						<CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
							<KeyRound className="h-5 w-5 text-primary" />
							Configure Target Authentication
						</CardTitle>
						<CardDescription className="text-xs">
							Provide credentials or session tokens if the assessment targets authenticated application workflows.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
							{[
								{ id: "none", label: "None / Anonymous" },
								{ id: "credentials", label: "Username & Password" },
								{ id: "bearer", label: "Bearer Token" },
								{ id: "cookie", label: "Session Cookie" },
								{ id: "apikey", label: "API Key Header" },
							].map((m) => (
								<button
									key={m.id}
									type="button"
									onClick={() => {
										setAuthMethod(m.id as any);
										setAuthTestStatus("not_configured");
									}}
									className={`
										px-3 py-2.5 rounded-lg border text-xs font-medium text-center transition-all
										${authMethod === m.id
											? "border-primary bg-primary/10 text-primary font-semibold"
											: "border-border/60 bg-card hover:bg-muted/50 text-muted-foreground"
										}
									`}
								>
									{m.label}
								</button>
							))}
						</div>

						{/* Dynamic Credential Inputs */}
						{authMethod === "credentials" && (
							<div className="p-4 rounded-xl bg-card border border-border/60 space-y-4">
								<div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
									<div className="space-y-1.5">
										<Label className="text-xs">Username / Email</Label>
										<Input
											value={targetUsername}
											onChange={(e) => setTargetUsername(e.target.value)}
											className="text-xs font-mono"
										/>
									</div>
									<div className="space-y-1.5">
										<Label className="text-xs">Password</Label>
										<div className="relative">
											<Input
												type={showSecrets ? "text" : "password"}
												value={targetPassword}
												onChange={(e) => setTargetPassword(e.target.value)}
												className="text-xs font-mono pr-10"
											/>
											<button
												type="button"
												onClick={() => setShowSecrets(!showSecrets)}
												className="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground"
											>
												{showSecrets ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
											</button>
										</div>
									</div>
								</div>
								{targetType === "managed" && (
									<p className="text-[11px] text-muted-foreground">
										Pre-filled with default OWASP Juice Shop test credentials (<code className="text-foreground">admin@juice-sh.op</code>).
									</p>
								)}
							</div>
						)}

						{authMethod === "bearer" && (
							<div className="p-4 rounded-xl bg-card border border-border/60 space-y-2">
								<Label className="text-xs">Bearer Token (JWT)</Label>
								<Input
									value={bearerToken}
									onChange={(e) => setBearerToken(e.target.value)}
									placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
									className="text-xs font-mono"
								/>
							</div>
						)}

						{authMethod === "cookie" && (
							<div className="p-4 rounded-xl bg-card border border-border/60 space-y-2">
								<Label className="text-xs">Session Cookie String</Label>
								<Input
									value={sessionCookie}
									onChange={(e) => setSessionCookie(e.target.value)}
									placeholder="connect.sid=s%3A...; token=..."
									className="text-xs font-mono"
								/>
							</div>
						)}

						{authMethod === "apikey" && (
							<div className="p-4 rounded-xl bg-card border border-border/60 space-y-2">
								<Label className="text-xs">API Key / Authorization Header</Label>
								<Input
									value={apiKey}
									onChange={(e) => setApiKey(e.target.value)}
									placeholder="X-API-Key: sec_live_..."
									className="text-xs font-mono"
								/>
							</div>
						)}

						{/* Test Authentication Check */}
						<div className="flex items-center justify-between p-3.5 bg-muted/30 border border-border/60 rounded-xl">
							<div className="flex items-center gap-2">
								{authTestStatus === "success" ? (
									<CheckCircle2 className="h-4 w-4 text-emerald-400" />
								) : authTestStatus === "failed" ? (
									<XCircle className="h-4 w-4 text-rose-400" />
								) : (
									<Activity className="h-4 w-4 text-muted-foreground" />
								)}
								<span className="text-xs text-foreground font-medium">
									{authTestStatus === "success"
										? "Credentials verified successfully against target!"
										: authTestStatus === "failed"
										? "Credential test failed: invalid response or unreachable target."
										: authMethod === "none"
										? "Anonymous mode: no credentials required."
										: "Test credentials to ensure autonomous agents can establish session."}
								</span>
							</div>
							{authMethod !== "none" && (
								<Button
									size="sm"
									variant="outline"
									onClick={handleTestAuth}
									disabled={authTestStatus === "pending"}
									className="text-xs font-semibold gap-1.5"
								>
									{authTestStatus === "pending" ? "Testing..." : "Test Credentials"}
								</Button>
							)}
						</div>
					</CardContent>
					<CardFooter className="flex justify-between pt-4 border-t border-border/40">
						<Button
							variant="outline"
							onClick={() => setStep("target")}
							className="gap-2 text-xs"
						>
							<ArrowLeft className="h-4 w-4" />
							Back
						</Button>
						<Button
							onClick={() => setStep("scope")}
							className="gap-2 text-xs font-semibold"
						>
							Continue to Scope Review
							<ArrowRight className="h-4 w-4" />
						</Button>
					</CardFooter>
				</Card>
			)}

			{/* ================= STEP 4: REVIEW SCOPE ================= */}
			{step === "scope" && (
				<Card className="border-border/60 bg-card shadow-sm">
					<CardHeader>
						<CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
							<Shield className="h-5 w-5 text-primary" />
							Review Allowed and Excluded Scope
						</CardTitle>
						<CardDescription className="text-xs">
							Deterministic boundaries enforced by ScopeEnforcer. Out-of-scope requests are dropped before network transmission.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="space-y-1.5">
							<Label className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
								<CheckCircle2 className="h-3.5 w-3.5" />
								Allowed Endpoint Prefixes (In-Scope)
							</Label>
							<Input
								value={allowedPaths}
								onChange={(e) => setAllowedPaths(e.target.value)}
								className="text-xs font-mono"
							/>
							<p className="text-[11px] text-muted-foreground">
								Only URLs beginning with these path prefixes will be probed by security agents.
							</p>
						</div>

						<div className="space-y-1.5">
							<Label className="text-xs font-semibold text-rose-400 flex items-center gap-1.5">
								<XCircle className="h-3.5 w-3.5" />
								Excluded Endpoint Prefixes (Out-of-Scope / Denied)
							</Label>
							<Input
								value={blockedPaths}
								onChange={(e) => setBlockedPaths(e.target.value)}
								className="text-xs font-mono"
							/>
							<p className="text-[11px] text-muted-foreground">
								ScopeEnforcer deterministically drops network transmission to any excluded path.
							</p>
						</div>

						<div className="space-y-1.5">
							<Label className="text-xs font-semibold">Allowed HTTP Methods</Label>
							<Input
								value={allowedMethods}
								onChange={(e) => setAllowedMethods(e.target.value)}
								className="text-xs font-mono"
							/>
						</div>
					</CardContent>
					<CardFooter className="flex justify-between pt-4 border-t border-border/40">
						<Button
							variant="outline"
							onClick={() => setStep("auth")}
							className="gap-2 text-xs"
						>
							<ArrowLeft className="h-4 w-4" />
							Back
						</Button>
						<Button
							onClick={() => setStep("pre-flight")}
							className="gap-2 text-xs font-semibold"
						>
							Continue to Pre-Flight Checks
							<ArrowRight className="h-4 w-4" />
						</Button>
					</CardFooter>
				</Card>
			)}

			{/* ================= STEP 5: AUTHORIZATION & PRE-FLIGHT CHECKS ================= */}
			{step === "pre-flight" && (
				<Card className="border-border/60 bg-card shadow-sm">
					<CardHeader>
						<CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
							<Lock className="h-5 w-5 text-primary" />
							Configuration & Authorization Check
						</CardTitle>
						<CardDescription className="text-xs">
							Confirm operational parameters and cryptographic authorization before launching autonomous agents.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						{/* XBOW-inspired Configuration Check List */}
						<div className="space-y-3 p-4 bg-muted/20 border border-border/60 rounded-xl">
							<div className="flex items-center justify-between pb-2 border-b border-border/40">
								<span className="text-xs font-bold text-foreground">Parameter Check</span>
								<span className="text-xs font-bold text-foreground">Status</span>
							</div>

							<div className="flex items-center justify-between py-1">
								<div className="flex items-center gap-2.5">
									<CheckCircle2 className={`h-4 w-4 ${isConnected ? "text-emerald-400" : "text-amber-400"}`} />
									<div>
										<div className="text-xs font-semibold text-foreground">Connected</div>
										<div className="text-[11px] text-muted-foreground">
											Target is reachable at {targetType === "managed" ? (activeLab ? activeLab.browser_url || "http://127.0.0.1:5000" : "Loopback port 5000 (offline)") : (approvedExternalGrant ? approvedExternalGrant.authorized_host : "Pending verification")}
										</div>
									</div>
								</div>
								<Badge className={isConnected ? "bg-emerald-600/20 text-emerald-300 border-emerald-500/30 text-[10px]" : "bg-amber-500/20 text-amber-300 border-amber-500/30 text-[10px]"}>
									{isConnected ? "CONNECTED" : "NOT READY"}
								</Badge>
							</div>

							<div className="flex items-center justify-between py-1">
								<div className="flex items-center gap-2.5">
									<CheckCircle2 className={`h-4 w-4 ${isVerified ? "text-emerald-400" : "text-amber-400"}`} />
									<div>
										<div className="text-xs font-semibold text-foreground">Verified</div>
										<div className="text-[11px] text-muted-foreground">
											{authMethod === "none" ? "Anonymous baseline session verified" : "1 credential set verified"}
										</div>
									</div>
								</div>
								<Badge className={isVerified ? "bg-emerald-600/20 text-emerald-300 border-emerald-500/30 text-[10px]" : "bg-amber-500/20 text-amber-300 border-amber-500/30 text-[10px]"}>
									{isVerified ? "VERIFIED" : "UNTESTED"}
								</Badge>
							</div>

							<div className="flex items-center justify-between py-1">
								<div className="flex items-center gap-2.5">
									<CheckCircle2 className={`h-4 w-4 ${isScopingComplete ? "text-emerald-400" : "text-amber-400"}`} />
									<div>
										<div className="text-xs font-semibold text-foreground">Scoping Complete</div>
										<div className="text-[11px] text-muted-foreground">
											Deterministic allowed & excluded boundaries active
										</div>
									</div>
								</div>
								<Badge className={isScopingComplete ? "bg-emerald-600/20 text-emerald-300 border-emerald-500/30 text-[10px]" : "bg-amber-500/20 text-amber-300 border-amber-500/30 text-[10px]"}>
									{isScopingComplete ? "SCOPED" : "MISSING"}
								</Badge>
							</div>

							<div className="flex items-center justify-between py-1">
								<div className="flex items-center gap-2.5">
									<CheckCircle2 className={`h-4 w-4 ${isGrantValid ? "text-emerald-400" : "text-rose-400"}`} />
									<div>
										<div className="text-xs font-semibold text-foreground">Cryptographic Grant</div>
										<div className="text-[11px] text-muted-foreground">
											{targetType === "managed" ? (activeLab?.grant_id ? `Grant: ${activeLab.grant_id}` : "Practice lab grant required") : (approvedExternalGrant?.grant_id ? `Grant: ${approvedExternalGrant.grant_id}` : "Two-person approval required")}
										</div>
									</div>
								</div>
								<Badge className={isGrantValid ? "bg-emerald-600/20 text-emerald-300 border-emerald-500/30 text-[10px]" : "bg-rose-500/20 text-rose-300 border-rose-500/30 text-[10px]"}>
									{isGrantValid ? "AUTHORIZED" : "UNAUTHORIZED"}
								</Badge>
							</div>
						</div>

						{/* Missing grant resolution guidance */}
						{!isConnected && targetType === "managed" && (
							<Alert className="py-2.5 bg-amber-500/10 border-amber-500/30 text-amber-300">
								<AlertTriangle className="h-4 w-4" />
								<AlertTitle className="text-xs font-semibold">Practice Lab is Not Running</AlertTitle>
								<AlertDescription className="text-xs mt-1">
									Start the practice lab before launching the assessment.
									<Button
										size="sm"
										onClick={onStartLab}
										disabled={isStartingLab}
										className="ml-3 text-[11px] bg-emerald-600 hover:bg-emerald-500 text-white font-semibold"
									>
										Launch Practice Lab
									</Button>
								</AlertDescription>
							</Alert>
						)}
					</CardContent>
					<CardFooter className="flex justify-between pt-4 border-t border-border/40">
						<Button
							variant="outline"
							onClick={() => setStep("scope")}
							className="gap-2 text-xs"
						>
							<ArrowLeft className="h-4 w-4" />
							Back
						</Button>
						<Button
							onClick={() => setStep("review-launch")}
							disabled={!canProceedToLaunch}
							className="gap-2 text-xs font-semibold"
						>
							Continue to Review & Launch
							<ArrowRight className="h-4 w-4" />
						</Button>
					</CardFooter>
				</Card>
			)}

			{/* ================= STEP 6: REVIEW & LAUNCH ================= */}
			{step === "review-launch" && (
				<Card className="border-border/60 bg-card shadow-sm">
					<CardHeader>
						<CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
							<Play className="h-5 w-5 text-primary" />
							Review and Launch Assessment
						</CardTitle>
						<CardDescription className="text-xs">
							Confirm operational parameters before deploying autonomous security testing agents.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
							<div className="p-3.5 rounded-xl bg-card border border-border/60 space-y-2">
								<span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Template & Mode</span>
								<div className="text-sm font-bold text-foreground">
									{assessmentTemplate === "comprehensive"
										? "Comprehensive Web Assessment"
										: assessmentTemplate === "enumeration"
										? "Surface Enumeration"
										: "Targeted Retest"}
								</div>
								<div className="text-xs text-muted-foreground">
									Rules of Engagement: BROAD mode with deterministic ScopeEnforcer bounds
								</div>
							</div>

							<div className="p-3.5 rounded-xl bg-card border border-border/60 space-y-2">
								<span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Target System</span>
								<div className="text-sm font-bold text-foreground">
									{targetType === "managed" ? "OWASP Juice Shop (Managed Lab)" : (appName || extHost)}
								</div>
								<div className="text-xs font-mono text-muted-foreground">
									{targetType === "managed" ? "http://127.0.0.1:5000" : `https://${extHost}:${extPort}`}
								</div>
							</div>

							<div className="p-3.5 rounded-xl bg-card border border-border/60 space-y-2">
								<span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Authentication</span>
								<div className="text-sm font-bold text-foreground capitalize">
									{authMethod === "none" ? "Anonymous Baseline" : `${authMethod} (${targetUsername || "Configured"})`}
								</div>
								<div className="text-xs text-muted-foreground">
									Session credentials pre-flight verified
								</div>
							</div>

							<div className="p-3.5 rounded-xl bg-card border border-border/60 space-y-2">
								<span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Scope Bounds</span>
								<div className="text-xs font-mono text-emerald-400 truncate">
									In-Scope: {allowedPaths}
								</div>
								<div className="text-xs font-mono text-rose-400 truncate">
									Denied: {blockedPaths}
								</div>
							</div>
						</div>

						<Alert className="py-2.5 bg-primary/5 border-primary/20">
							<Shield className="h-4 w-4 text-primary" />
							<AlertTitle className="text-xs font-semibold">Autonomous Pentest Readiness</AlertTitle>
							<AlertDescription className="text-xs mt-0.5">
								Controlled MCP tools will execute under deterministic ScopeEnforcer supervision. All findings will be corroborated with independent negative controls.
							</AlertDescription>
						</Alert>
					</CardContent>
					<CardFooter className="flex justify-between pt-4 border-t border-border/40">
						<Button
							variant="outline"
							onClick={() => setStep("pre-flight")}
							className="gap-2 text-xs"
						>
							<ArrowLeft className="h-4 w-4" />
							Back
						</Button>
						<Button
							onClick={handleLaunch}
							disabled={isStartingRun || !canProceedToLaunch}
							className="gap-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm px-6 py-5"
						>
							<Play className="h-4 w-4" />
							{isStartingRun ? "Launching Agents..." : "Launch Autonomous Pentest"}
						</Button>
					</CardFooter>
				</Card>
			)}
		</div>
	);
}
