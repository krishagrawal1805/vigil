import React, { useState, useEffect } from "react";
import {
	Globe,
	Shield,
	Lock,
	CheckCircle2,
	AlertTriangle,
	ArrowRight,
	ArrowLeft,
	Play,
	KeyRound,
	Zap,
	Layers,
	Loader2,
	SlidersHorizontal,
	ChevronDown,
	ChevronUp,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { AuthorizationGrant, CallerProfile, RegisterExternalRequest } from "@/store";

interface ExternalAssessmentWorkflowViewProps {
	profile?: CallerProfile;
	externalGrants?: AuthorizationGrant[];
	onRegisterExternal: (payload: RegisterExternalRequest) => Promise<any>;
	isRegisteringExt: boolean;
	onVerifyDNS?: (asmId: string, token: string) => Promise<any>;
	isVerifyingDNS?: boolean;
	onApproveExternal?: (asmId: string, evidenceRef?: string) => Promise<any>;
	isApprovingExt?: boolean;
	onRevokeGrant?: (grantId: string) => Promise<any>;
	isRevokingGrant?: boolean;
	onStartAssessment: (grantId?: string, targetUrl?: string) => Promise<void>;
	isStartingRun: boolean;
	onNavigate: (view: string, subTab?: string) => void;
}

export function ExternalAssessmentWorkflowView({
	profile,
	externalGrants,
	onRegisterExternal,
	isRegisteringExt,
	onStartAssessment,
	isStartingRun,
	onNavigate,
}: ExternalAssessmentWorkflowViewProps) {
	// Target inputs persisted in sessionStorage
	const [websiteUrl, setWebsiteUrlState] = useState<string>(
		() => sessionStorage.getItem("vigil_ext_website_url") || ""
	);
	const [targetHost, setTargetHostState] = useState<string>(
		() => sessionStorage.getItem("vigil_ext_target_host") || ""
	);
	const [targetPort, setTargetPortState] = useState<number>(() => {
		const saved = sessionStorage.getItem("vigil_ext_target_port");
		return saved ? parseInt(saved, 10) : 443;
	});
	const [urlError, setUrlError] = useState<string | null>(null);

	// Profile selection
	const [scanProfile, setScanProfile] = useState<"comprehensive" | "surface">("comprehensive");

	// Scope boundaries
	const [allowedPaths, setAllowedPathsState] = useState<string>(
		() => sessionStorage.getItem("vigil_ext_allowed_paths") || "/api/, /rest/, /v1/"
	);
	const [blockedPaths, setBlockedPathsState] = useState<string>(
		() => sessionStorage.getItem("vigil_ext_blocked_paths") || "/admin/logout, /payments/execute"
	);

	// Optional authentication
	const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
	const [authHeader, setAuthHeader] = useState<string>(
		() => sessionStorage.getItem("vigil_ext_auth_header") || ""
	);
	const [sessionCookie, setSessionCookie] = useState<string>(
		() => sessionStorage.getItem("vigil_ext_session_cookie") || ""
	);

	// Ownership certification checkbox
	const [certified, setCertified] = useState<boolean>(false);
	const [launchError, setLaunchError] = useState<string | null>(null);
	const [isLaunching, setIsLaunching] = useState<boolean>(false);

	// Sync handlers
	const handleUrlChange = (val: string) => {
		setWebsiteUrlState(val);
		sessionStorage.setItem("vigil_ext_website_url", val);
		setUrlError(null);
		setLaunchError(null);

		const trimmed = val.trim();
		if (!trimmed) {
			setTargetHostState("");
			return;
		}

		try {
			let toParse = trimmed;
			if (!toParse.startsWith("http://") && !toParse.startsWith("https://")) {
				toParse = "https://" + toParse;
			}
			const parsed = new URL(toParse);
			const host = parsed.hostname;
			const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === "https:" ? 443 : 80;

			setTargetHostState(host);
			setTargetPortState(port);
			sessionStorage.setItem("vigil_ext_target_host", host);
			sessionStorage.setItem("vigil_ext_target_port", port.toString());
		} catch {
			setUrlError("Please enter a valid URL (e.g. https://app.example.com)");
		}
	};

	const setAllowedPaths = (val: string) => {
		setAllowedPathsState(val);
		sessionStorage.setItem("vigil_ext_allowed_paths", val);
	};

	const setBlockedPaths = (val: string) => {
		setBlockedPathsState(val);
		sessionStorage.setItem("vigil_ext_blocked_paths", val);
	};

	// 1-Click Launch: Registers, Auto-Approves, and Starts Assessment
	const handleLaunchAssessment = async () => {
		setLaunchError(null);

		if (!websiteUrl.trim() || !targetHost) {
			setLaunchError("Please enter a valid target URL before starting the assessment.");
			return;
		}
		if (!certified) {
			setLaunchError("Please certify that you have authorization to assess this target.");
			return;
		}

		setIsLaunching(true);
		try {
			// 1. Register & auto-authorize grant in 1 step
			const regRes = await onRegisterExternal({
				target_host: targetHost,
				target_port: targetPort,
				allowed_paths: allowedPaths.split(",").map((s) => s.trim()).filter(Boolean),
				blocked_paths: blockedPaths.split(",").map((s) => s.trim()).filter(Boolean),
				auto_approve: true,
			});

			const grantId = regRes?.grant?.grant_id;
			if (!grantId) {
				throw new Error("Target registration succeeded but grant ID was not minted.");
			}

			// 2. Launch autonomous multi-agent pentest run immediately
			await onStartAssessment(grantId, websiteUrl);

			// 3. Navigate directly to live assessment screen
			onNavigate("live-assessment");
		} catch (err: any) {
			setLaunchError(
				err?.data?.error ||
				err?.message ||
				"Failed to launch assessment. Please verify target reachability."
			);
		} finally {
			setIsLaunching(false);
		}
	};

	return (
		<div className="max-w-3xl mx-auto py-6 sm:py-10 space-y-6 animate-in fade-in duration-200">
			{/* Breadcrumb Navigation */}
			<div className="flex items-center justify-between">
				<Button
					variant="ghost"
					size="sm"
					onClick={() => onNavigate("welcome")}
					className="gap-1.5 text-xs text-slate-600 hover:text-slate-900 -ml-2 font-medium"
				>
					<ArrowLeft className="h-3.5 w-3.5" />
					Back to Test Categories
				</Button>
				<Badge variant="outline" className="text-xs px-2.5 py-0.5 text-blue-700 border-blue-200 bg-blue-50 font-semibold">
					External Target
				</Badge>
			</div>

			{/* Clean, Direct Header */}
			<div className="space-y-1">
				<h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 flex items-center gap-2.5">
					<Globe className="h-7 w-7 text-blue-600" />
					Web Application Pentest
				</h1>
				<p className="text-xs sm:text-sm text-slate-600">
					Enter your target web application URL. VIGIL autonomously discovers endpoints, probes OWASP vulnerabilities, and verifies exploits.
				</p>
			</div>

			{launchError && (
				<Alert variant="destructive" className="py-2.5">
					<AlertTriangle className="h-4 w-4" />
					<AlertDescription className="text-xs">{launchError}</AlertDescription>
				</Alert>
			)}

			{/* Main Single-Step Target Card */}
			<Card className="border border-slate-200 bg-white shadow-sm overflow-hidden">
				<CardHeader className="pb-4 border-b border-slate-100">
					<CardTitle className="text-base font-bold text-slate-900 flex items-center justify-between">
						<span>Target Configuration</span>
						<Badge variant="outline" className="text-[10px] font-mono text-emerald-700 bg-emerald-50 border-emerald-300">
							1-Click Launch
						</Badge>
					</CardTitle>
					<CardDescription className="text-xs text-slate-500">
						Configure target parameters and authorization bounds before launching AI security testing.
					</CardDescription>
				</CardHeader>

				<CardContent className="p-6 space-y-6">
					{/* 1. Target URL Input */}
					<div className="space-y-2">
						<Label className="text-xs font-semibold text-slate-800 uppercase tracking-wider">
							Target Website or API URL
						</Label>
						<Input
							value={websiteUrl}
							onChange={(e) => handleUrlChange(e.target.value)}
							placeholder="https://app.example.com"
							className="text-sm font-mono h-11 border-slate-300 focus:border-blue-500 bg-slate-50/50"
							autoFocus
						/>
						{urlError ? (
							<p className="text-[11px] text-rose-500 font-medium">{urlError}</p>
						) : targetHost ? (
							<div className="flex items-center gap-2 text-xs font-mono text-slate-600 bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-200">
								<CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
								<span>Host: <strong className="text-slate-900">{targetHost}</strong></span>
								<span className="text-slate-300">•</span>
								<span>Port: <strong className="text-slate-900">{targetPort}</strong></span>
								<span className="text-slate-300">•</span>
								<span>Protocol: <strong className="text-slate-900">{targetPort === 443 ? "HTTPS" : "HTTP"}</strong></span>
							</div>
						) : (
							<p className="text-[11px] text-slate-500">
								Specify the fully qualified domain name or IP address (e.g. <code>https://app.example.com</code> or <code>http://127.0.0.1:5000</code>).
							</p>
						)}
					</div>

					{/* 2. Assessment Profile Selector */}
					<div className="space-y-2">
						<Label className="text-xs font-semibold text-slate-800 uppercase tracking-wider">
							Assessment Profile
						</Label>
						<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
							<div
								onClick={() => setScanProfile("comprehensive")}
								className={`
									p-3.5 rounded-xl border-2 cursor-pointer transition-all flex flex-col justify-between gap-2
									${scanProfile === "comprehensive" ? "border-blue-600 bg-blue-50/40 shadow-xs" : "border-slate-200 hover:border-slate-300 bg-white"}
								`}
							>
								<div className="flex items-center justify-between">
									<div className="flex items-center gap-2 font-bold text-xs text-slate-900">
										<Zap className="h-4 w-4 text-blue-600" />
										<span>Comprehensive Pentest</span>
									</div>
									<Badge className="bg-blue-600 text-white text-[9px] font-semibold py-0">RECOMMENDED</Badge>
								</div>
								<p className="text-[11px] text-slate-600 leading-relaxed">
									Full autonomous testing: BOLA/IDOR authorization probing, SQL injection, reflected & DOM XSS, and exploit proof generation.
								</p>
							</div>

							<div
								onClick={() => setScanProfile("surface")}
								className={`
									p-3.5 rounded-xl border-2 cursor-pointer transition-all flex flex-col justify-between gap-2
									${scanProfile === "surface" ? "border-blue-600 bg-blue-50/40 shadow-xs" : "border-slate-200 hover:border-slate-300 bg-white"}
								`}
							>
								<div className="flex items-center justify-between">
									<div className="flex items-center gap-2 font-bold text-xs text-slate-900">
										<Layers className="h-4 w-4 text-slate-600" />
										<span>Surface Reconnaissance</span>
									</div>
									<Badge variant="outline" className="text-[9px] text-slate-600">PASSIVE</Badge>
								</div>
								<p className="text-[11px] text-slate-600 leading-relaxed">
									Lightweight attack surface discovery, OpenAPI/Swagger route mapping, security headers audit, and safe non-destructive probing.
								</p>
							</div>
						</div>
					</div>

					{/* 3. Scope Boundaries */}
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-100">
						<div className="space-y-1.5">
							<Label className="text-xs font-medium text-slate-700">Allowed Path Prefixes</Label>
							<Input
								value={allowedPaths}
								onChange={(e) => setAllowedPaths(e.target.value)}
								placeholder="/api/, /rest/, /v1/"
								className="text-xs font-mono h-9 border-slate-300"
							/>
							<p className="text-[10px] text-slate-500">Only endpoints matching these path prefixes will be probed.</p>
						</div>

						<div className="space-y-1.5">
							<Label className="text-xs font-medium text-slate-700">Excluded Safety Paths</Label>
							<Input
								value={blockedPaths}
								onChange={(e) => setBlockedPaths(e.target.value)}
								placeholder="/admin/logout, /payments/execute"
								className="text-xs font-mono h-9 border-slate-300"
							/>
							<p className="text-[10px] text-slate-500">Requests matching excluded paths are dropped immediately.</p>
						</div>
					</div>

					{/* 4. Optional Advanced Authentication Accordion */}
					<div className="border border-slate-200 rounded-xl overflow-hidden">
						<button
							type="button"
							onClick={() => setShowAdvanced(!showAdvanced)}
							className="w-full flex items-center justify-between px-4 py-2.5 bg-slate-50 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors"
						>
							<span className="flex items-center gap-2">
								<KeyRound className="h-3.5 w-3.5 text-slate-500" />
								<span>Target Authentication (Bearer Token / Cookie) — Optional</span>
							</span>
							{showAdvanced ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
						</button>
						{showAdvanced && (
							<div className="p-4 bg-white space-y-3 border-t border-slate-200">
								<div className="space-y-1.5">
									<Label className="text-xs font-medium text-slate-700">Authorization Header (Bearer token)</Label>
									<Input
										value={authHeader}
										onChange={(e) => {
											setAuthHeader(e.target.value);
											sessionStorage.setItem("vigil_ext_auth_header", e.target.value);
										}}
										placeholder="Bearer eyJhbGciOiJIUzI1NiIsIn..."
										className="text-xs font-mono h-9"
									/>
								</div>
								<div className="space-y-1.5">
									<Label className="text-xs font-medium text-slate-700">Session Cookie</Label>
									<Input
										value={sessionCookie}
										onChange={(e) => {
											setSessionCookie(e.target.value);
											sessionStorage.setItem("vigil_ext_session_cookie", e.target.value);
										}}
										placeholder="session_id=abc123xyz"
										className="text-xs font-mono h-9"
									/>
								</div>
							</div>
						)}
					</div>

					{/* 5. Authorization Certification */}
					<div className="p-4 rounded-xl bg-blue-50/60 border border-blue-200 space-y-2">
						<label className="flex items-start gap-3 cursor-pointer">
							<input
								type="checkbox"
								checked={certified}
								onChange={(e) => setCertified(e.target.checked)}
								className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
							/>
							<span className="text-xs text-slate-700 leading-relaxed font-medium">
								I certify that my organization owns <strong>{targetHost || "this target"}</strong> or possesses explicit, documented authorization to conduct autonomous security penetration testing.
							</span>
						</label>
					</div>
				</CardContent>

				{/* 6. Launch Footer */}
				<CardFooter className="bg-slate-50/70 px-6 py-4 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3">
					<div className="text-xs text-slate-500 flex items-center gap-1.5">
						<Shield className="h-3.5 w-3.5 text-emerald-600" />
						<span>Autonomous multi-agent orchestration with deterministic scope bounds</span>
					</div>

					<Button
						onClick={handleLaunchAssessment}
						disabled={!websiteUrl.trim() || !certified || isLaunching || isStartingRun || isRegisteringExt}
						className="w-full sm:w-auto px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-sm gap-2"
					>
						{isLaunching || isStartingRun || isRegisteringExt ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								<span>Launching Assessment...</span>
							</>
						) : (
							<>
								<Play className="h-4 w-4" />
								<span>Start Autonomous Pentest</span>
								<ArrowRight className="h-4 w-4" />
							</>
						)}
					</Button>
				</CardFooter>
			</Card>
		</div>
	);
}
