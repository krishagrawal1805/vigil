import React, { useState } from "react";
import {
	Shield,
	Lock,
	CheckCircle2,
	ArrowRight,
	Play,
	Layers,
	Cpu,
	Terminal,
	FileText,
	KeyRound,
	Search,
	Crosshair,
	Activity,
	Zap,
	AlertTriangle,
	Eye,
	Fingerprint,
	ChevronRight,
	ExternalLink,
	ShieldAlert,
	ShieldCheck,
	Workflow,
	Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

interface PublicLandingPageProps {
	onGetStarted: () => void;
	onSignIn: () => void;
}

export function PublicLandingPage({ onGetStarted, onSignIn }: PublicLandingPageProps) {
	const [activeStage, setActiveStage] = useState<number>(0);

	const capabilities = [
		{
			icon: <Cpu className="h-5 w-5 text-cyan-400" />,
			title: "Multi-Agent Security Orchestration",
			description:
				"Specialized AI security agents coordinate under an authoritative Primary Orchestrator to plan, execute, and cross-corroborate penetration testing missions.",
		},
		{
			icon: <Search className="h-5 w-5 text-blue-400" />,
			title: "Automated Attack-Surface Discovery",
			description:
				"Autonomous enumeration discovers accessible web endpoints, query parameters, hidden API routes, and service technologies strictly within authorized bounds.",
		},
		{
			icon: <Crosshair className="h-5 w-5 text-emerald-400" />,
			title: "Controlled Vulnerability Testing",
			description:
				"Probes for Broken Object-Level Authorization (BOLA/IDOR), cryptographic JWT flaws, and input injection using low-impact, non-destructive payloads.",
		},
		{
			icon: <Lock className="h-5 w-5 text-amber-400" />,
			title: "Deterministic ScopeEnforcer Boundaries",
			description:
				"Deterministic outbound request enforcement strictly verifies allowed CIDR ranges, FQDNs, ports, and URI paths. Excluded paths always override inclusions.",
		},
		{
			icon: <Fingerprint className="h-5 w-5 text-purple-400" />,
			title: "Cryptographic Target Authorization",
			description:
				"Requires proof of ownership via cryptographic DNS TXT challenge tokens and digital authorization grants before testing external domains.",
		},
		{
			icon: <ShieldCheck className="h-5 w-5 text-emerald-400" />,
			title: "Independent Vulnerability Verification",
			description:
				"Candidate findings produced by attack agents must be independently verified by an isolated validator engine before being recognized as confirmed.",
		},
		{
			icon: <Activity className="h-5 w-5 text-rose-400" />,
			title: "Negative Control Validation",
			description:
				"Every confirmed exploit executes differential negative control requests to mathematically eliminate false positives and transient server anomalies.",
		},
		{
			icon: <FileText className="h-5 w-5 text-cyan-400" />,
			title: "Evidence-Backed Reports",
			description:
				"Every finding includes full HTTP request/response proofs, exact cURL reproduction commands, CVSS 3.1 scoring, and actionable remediation diffs.",
		},
		{
			icon: <Terminal className="h-5 w-5 text-indigo-400" />,
			title: "Tamper-Evident Audit Records",
			description:
				"Real-time append-only cryptographic event logging documents every agent decision, tool invocation, scope evaluation, and operator action.",
		},
	];

	const workflowStages = [
		{
			num: "01",
			title: "Discover",
			subtitle: "Understand the application attack surface",
			description:
				"The Reconnaissance Agent crawls target endpoints, extracts HTML forms, inspects API schemas, and maps attack surfaces within strict ScopeEnforcer boundaries.",
			details: [
				"Deterministic crawling and route enumeration",
				"Header, method, and parameter profiling",
				"Scope boundary enforcement on every request",
			],
			badge: "Phase 1: Reconnaissance",
		},
		{
			num: "02",
			title: "Investigate",
			subtitle: "Dispatch specialist security testing tasks",
			description:
				"The Planning Agent analyzes discovered endpoints and dispatches specialist roles—probing authorization boundaries, cryptographic tokens, and input parameters.",
			details: [
				"Structured hypothesis generation",
				"Specialized tools: BOLA probe, JWT inspector, injection tester",
				"Controlled, rate-limited payload delivery",
			],
			badge: "Phase 2: Execution",
		},
		{
			num: "03",
			title: "Verify",
			subtitle: "Independently validate suspected vulnerabilities",
			description:
				"Candidate findings are handed to an independent Validator Agent that re-tests the exploit and runs negative controls to eliminate false positives.",
			details: [
				"Authoritative exploit corroboration",
				"Negative control differential checks",
				"Unique validator decision IDs and evidence hashes",
			],
			badge: "Phase 3: Validation",
		},
		{
			num: "04",
			title: "Report",
			subtitle: "Generate technical evidence and remediation",
			description:
				"The Reporting Agent compiles confirmed findings with CVSS 3.1 scoring, raw HTTP reproduction evidence, and targeted code remediation advice.",
			details: [
				"Exportable Markdown & executive reports",
				"Tamper-evident audit log ledger",
				"Exact cURL reproduction commands",
			],
			badge: "Phase 4: Intelligence",
		},
	];

	const agentRoles = [
		{
			name: "Primary Orchestrator",
			role: "Mission Commander & Ledger Coordinator",
			description:
				"Maintains mission state, enforces phase transitions, handles tool approval gates, and synchronizes telemetry across all subagents.",
			color: "border-primary/50 bg-primary/5 text-primary",
		},
		{
			name: "Reconnaissance Agent",
			role: "Attack Surface Mapping",
			description:
				"Discovers endpoints, parses API structures, and inspects HTTP response headers within strictly authorized domain and path boundaries.",
			color: "border-blue-500/50 bg-blue-500/5 text-blue-400",
		},
		{
			name: "Planning Agent",
			role: "Hypothesis Formulation",
			description:
				"Evaluates discovered routes against common architectural vulnerability patterns to prioritize targeted security hypotheses.",
			color: "border-indigo-500/50 bg-indigo-500/5 text-indigo-400",
		},
		{
			name: "Injection Testing Agent",
			role: "Input Validation Specialist",
			description:
				"Probes query and body parameters with benign marker payloads to identify SQL injection, BOLA/IDOR, and input reflection vulnerabilities.",
			color: "border-rose-500/50 bg-rose-500/5 text-rose-400",
		},
		{
			name: "Authentication & JWT Agent",
			role: "Identity & Cryptography Specialist",
			description:
				"Evaluates token entropy, algorithm confusion (none/HS256/RS256), signature verification, and session lifecycle boundaries.",
			color: "border-purple-500/50 bg-purple-500/5 text-purple-400",
		},
		{
			name: "Web Application Security Agent",
			role: "Authorization & Logic Specialist",
			description:
				"Probes Broken Object-Level Authorization (BOLA/IDOR), multi-tenant isolation, cross-account data leakage, and CORS misconfigurations.",
			color: "border-amber-500/50 bg-amber-500/5 text-amber-400",
		},
		{
			name: "Independent Validation Agent",
			role: "Adversarial Quality Control",
			description:
				"Operates in an isolated execution sandbox to reproduce candidate exploits and apply differential negative controls. Confirms or rejects findings.",
			color: "border-emerald-500/50 bg-emerald-500/5 text-emerald-400",
		},
		{
			name: "Reporting Agent",
			role: "Technical Intelligence & Remediation",
			description:
				"Aggregates confirmed evidence records, assigns CVSS 3.1 scores, maps MITRE ATT&CK techniques, and generates actionable fix guidance.",
			color: "border-cyan-500/50 bg-cyan-500/5 text-cyan-400",
		},
	];

	return (
		<div className="min-h-screen bg-background text-foreground flex flex-col selection:bg-primary/20 selection:text-primary">
			{/* Top Marketing Navigation Header */}
			<header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/80 backdrop-blur-md">
				<div className="max-w-7xl mx-auto flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
					<div className="flex items-center gap-3">
						<div className="h-9 w-9 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center shadow-sm">
							<Shield className="h-5 w-5 text-primary" />
						</div>
						<div className="flex flex-col">
							<span className="text-lg font-black tracking-widest text-foreground">VIGIL</span>
							<span className="text-[9px] font-mono tracking-wider text-primary uppercase -mt-1">
								Autonomous Security Intelligence
							</span>
						</div>
					</div>

					<nav className="hidden md:flex items-center gap-6 text-xs font-medium text-muted-foreground">
						<a href="#capabilities" className="hover:text-foreground transition-colors">
							Capabilities
						</a>
						<a href="#how-it-works" className="hover:text-foreground transition-colors">
							How It Works
						</a>
						<a href="#architecture" className="hover:text-foreground transition-colors">
							Specialist Agents
						</a>
						<a href="#security" className="hover:text-foreground transition-colors">
							Security & Scoping
						</a>
					</nav>

					<div className="flex items-center gap-3">
						<Button
							variant="ghost"
							size="sm"
							onClick={onSignIn}
							className="text-xs font-semibold text-muted-foreground hover:text-foreground"
						>
							Sign In
						</Button>
						<Button
							size="sm"
							onClick={onGetStarted}
							className="text-xs font-semibold gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
						>
							Get Started
							<ArrowRight className="h-3.5 w-3.5" />
						</Button>
					</div>
				</div>
			</header>

			{/* HERO SECTION */}
			<section className="relative overflow-hidden pt-16 pb-20 sm:pt-24 sm:pb-28 border-b border-border/30">
				{/* Background Grid Pattern */}
				<div
					className="absolute inset-0 opacity-[0.03] pointer-events-none"
					style={{
						backgroundImage:
							"linear-gradient(rgba(56,189,248,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.5) 1px, transparent 1px)",
						backgroundSize: "48px 48px",
					}}
				/>

				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
					<div className="text-center max-w-3xl mx-auto space-y-6">
						{/* Product Category Pill */}
						<div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/25 text-primary text-xs font-semibold tracking-wide">
							<Sparkles className="h-3.5 w-3.5" />
							Autonomous AI Penetration Testing
						</div>

						{/* Primary Headline */}
						<h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-foreground leading-[1.1]">
							Autonomous Penetration Testing.{" "}
							<span className="text-transparent bg-clip-text bg-gradient-to-r from-primary via-cyan-400 to-blue-500">
								Verified Security.
							</span>
						</h1>

						{/* Supporting Description */}
						<p className="text-base sm:text-lg text-muted-foreground leading-relaxed max-w-2xl mx-auto">
							VIGIL coordinates specialist AI security agents to discover application attack surfaces, execute controlled security tests, independently verify vulnerabilities, and generate actionable technical evidence.
						</p>

						{/* CTAs */}
						<div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-4">
							<Button
								size="lg"
								onClick={onGetStarted}
								className="w-full sm:w-auto gap-2 px-7 py-6 text-sm font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-lg shadow-primary/20"
							>
								Get Started
								<ArrowRight className="h-4 w-4" />
							</Button>
							<Button
								size="lg"
								variant="outline"
								onClick={() => {
									const el = document.getElementById("how-it-works");
									el?.scrollIntoView({ behavior: "smooth" });
								}}
								className="w-full sm:w-auto gap-2 px-7 py-6 text-sm font-semibold border-border/80 hover:bg-muted/50"
							>
								<Workflow className="h-4 w-4 text-primary" />
								Explore How It Works
							</Button>
						</div>

						{/* Security Credibility Badges */}
						<div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-8 text-xs text-muted-foreground border-t border-border/40 mt-8">
							<div className="flex items-center justify-center gap-1.5 p-2 rounded-lg bg-card/50 border border-border/40">
								<Lock className="h-3.5 w-3.5 text-primary" />
								<span>ScopeEnforcer™ Gated</span>
							</div>
							<div className="flex items-center justify-center gap-1.5 p-2 rounded-lg bg-card/50 border border-border/40">
								<ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
								<span>Independent Finding Verification</span>
							</div>
							<div className="flex items-center justify-center gap-1.5 p-2 rounded-lg bg-card/50 border border-border/40">
								<Fingerprint className="h-3.5 w-3.5 text-blue-400" />
								<span>DNS TXT Authorization</span>
							</div>
							<div className="flex items-center justify-center gap-1.5 p-2 rounded-lg bg-card/50 border border-border/40">
								<Terminal className="h-3.5 w-3.5 text-purple-400" />
								<span>Verifiable Evidence Ledger</span>
							</div>
						</div>
					</div>
				</div>
			</section>

			{/* PRODUCT CAPABILITIES SECTION */}
			<section id="capabilities" className="py-20 sm:py-24 border-b border-border/30 bg-muted/10">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="text-center max-w-2xl mx-auto mb-14 space-y-3">
						<Badge variant="outline" className="text-primary border-primary/30 text-xs font-mono">
							CORE CAPABILITIES
						</Badge>
						<h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
							Enterprise-Grade Autonomous Testing
						</h2>
						<p className="text-xs sm:text-sm text-muted-foreground">
							Engineered with strict safety controls, deterministic network enforcement, and mathematical exploit verification.
						</p>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
						{capabilities.map((cap, i) => (
							<Card
								key={i}
								className="border-border/60 bg-card hover:border-primary/50 transition-all duration-200 shadow-sm flex flex-col justify-between"
							>
								<CardHeader className="pb-3">
									<div className="h-10 w-10 rounded-xl bg-card border border-border/80 flex items-center justify-center mb-3 shadow-inner">
										{cap.icon}
									</div>
									<CardTitle className="text-sm font-bold text-foreground">
										{cap.title}
									</CardTitle>
								</CardHeader>
								<CardContent>
									<p className="text-xs text-muted-foreground leading-relaxed">
										{cap.description}
									</p>
								</CardContent>
							</Card>
						))}
					</div>
				</div>
			</section>

			{/* HOW VIGIL WORKS (4-STAGE WORKFLOW) */}
			<section id="how-it-works" className="py-20 sm:py-24 border-b border-border/30">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="text-center max-w-2xl mx-auto mb-14 space-y-3">
						<Badge variant="outline" className="text-emerald-400 border-emerald-500/30 text-xs font-mono">
							SYSTEM WORKFLOW
						</Badge>
						<h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
							How VIGIL Works
						</h2>
						<p className="text-xs sm:text-sm text-muted-foreground">
							A deterministic four-stage lifecycle from initial endpoint discovery to independently verified findings.
						</p>
					</div>

					{/* 4 Stage Interactive/Visual Cards */}
					<div className="grid grid-cols-1 md:grid-cols-4 gap-4">
						{workflowStages.map((stg, idx) => (
							<div
								key={stg.num}
								onClick={() => setActiveStage(idx)}
								className={`
									p-6 rounded-2xl border-2 transition-all cursor-pointer flex flex-col justify-between relative
									${
										activeStage === idx
											? "border-primary bg-primary/5 shadow-md"
											: "border-border/60 bg-card hover:border-primary/40"
									}
								`}
							>
								<div className="space-y-4">
									<div className="flex items-center justify-between">
										<span className="text-3xl font-black font-mono text-primary/40">
											{stg.num}
										</span>
										<Badge variant="outline" className="text-[10px] font-mono">
											{stg.badge}
										</Badge>
									</div>
									<div>
										<h3 className="text-lg font-bold text-foreground">{stg.title}</h3>
										<p className="text-xs font-medium text-primary mt-0.5">{stg.subtitle}</p>
									</div>
									<p className="text-xs text-muted-foreground leading-relaxed">
										{stg.description}
									</p>
								</div>

								<div className="space-y-2 border-t border-border/40 pt-4 mt-4">
									{stg.details.map((d, i) => (
										<div key={i} className="flex items-center gap-2 text-[11px] text-muted-foreground">
											<CheckCircle2 className="h-3 w-3 text-emerald-400 flex-shrink-0" />
											<span>{d}</span>
										</div>
									))}
								</div>
							</div>
						))}
					</div>
				</div>
			</section>

			{/* SPECIALIST AGENT ARCHITECTURE */}
			<section id="architecture" className="py-20 sm:py-24 border-b border-border/30 bg-muted/10">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="text-center max-w-2xl mx-auto mb-10 space-y-3">
						<Badge variant="outline" className="text-indigo-400 border-indigo-500/30 text-xs font-mono">
							AGENT ARCHITECTURE
						</Badge>
						<h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
							Specialist Security Agent Roles
						</h2>
						<p className="text-xs sm:text-sm text-muted-foreground">
							Rather than a generic monolithic model, VIGIL dispatches specialized roles with dedicated system prompts and restricted tool privileges.
						</p>
					</div>

					{/* Architectural execution note */}
					<div className="max-w-3xl mx-auto mb-8 p-3.5 rounded-xl bg-card border border-border/60 flex items-center gap-3 text-xs text-muted-foreground">
						<Activity className="h-4 w-4 text-primary flex-shrink-0" />
						<p>
							<strong className="text-foreground">Systematic Execution Model:</strong> Specialist agent roles execute systematically and sequentially according to mission phases under the Primary Orchestrator, guaranteeing predictable coordination rather than unmanaged concurrent execution.
						</p>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
						{agentRoles.map((agent, i) => (
							<div
								key={i}
								className={`p-5 rounded-xl border ${agent.color} flex flex-col justify-between transition-all hover:scale-[1.01]`}
							>
								<div className="space-y-2">
									<div className="flex items-center justify-between">
										<Badge variant="outline" className="text-[10px] uppercase font-mono">
											Role #{i + 1}
										</Badge>
										<span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
									</div>
									<h3 className="text-sm font-bold text-foreground">{agent.name}</h3>
									<p className="text-[11px] font-semibold text-primary">{agent.role}</p>
									<p className="text-xs text-muted-foreground leading-relaxed pt-1">
										{agent.description}
									</p>
								</div>
								<div className="mt-4 pt-2 border-t border-border/30 flex items-center text-[10px] text-muted-foreground font-mono">
									<span>Controlled MCP Sandboxing</span>
								</div>
							</div>
						))}
					</div>
				</div>
			</section>

			{/* SECURITY AND AUTHORIZATION SECTION */}
			<section id="security" className="py-20 sm:py-24 border-b border-border/30">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
					<div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
						<div className="space-y-6">
							<div>
								<Badge variant="outline" className="text-amber-400 border-amber-500/30 text-xs font-mono mb-2">
									SAFETY & GOVERNANCE
								</Badge>
								<h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
									Zero Unrestricted Testing. Deterministic Safety.
								</h2>
								<p className="text-xs sm:text-sm text-muted-foreground mt-2 leading-relaxed">
									VIGIL is engineered from the ground up for authorized, professional environments. Our architecture guarantees that no autonomous agent can wander outside defined boundaries or test unauthorized assets.
								</p>
							</div>

							<div className="space-y-4">
								<div className="flex items-start gap-3">
									<div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center flex-shrink-0 mt-0.5">
										<Lock className="h-4 w-4" />
									</div>
									<div>
										<h4 className="text-xs font-bold text-foreground">Deterministic Scope Enforcement</h4>
										<p className="text-xs text-muted-foreground mt-0.5">
											Deterministic outbound request enforcement inspects all outbound HTTP traffic. Any request targeting an IP, domain, port, or path not explicitly granted is dropped immediately.
										</p>
									</div>
								</div>

								<div className="flex items-start gap-3">
									<div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center flex-shrink-0 mt-0.5">
										<Fingerprint className="h-4 w-4" />
									</div>
									<div>
										<h4 className="text-xs font-bold text-foreground">Cryptographic Target Authorization</h4>
										<p className="text-xs text-muted-foreground mt-0.5">
											External target testing requires proving domain ownership via DNS TXT records (<code className="text-[10px] font-mono bg-muted px-1 py-0.5 rounded">_VIGIL-challenge.&lt;domain&gt;</code>) before any probe is authorized.
										</p>
									</div>
								</div>

								<div className="flex items-start gap-3">
									<div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center flex-shrink-0 mt-0.5">
										<ShieldAlert className="h-4 w-4" />
									</div>
									<div>
										<h4 className="text-xs font-bold text-foreground">Independent Two-Person Approval Rule</h4>
										<p className="text-xs text-muted-foreground mt-0.5">
											Separation of duties is enforced at the platform level: the user who registers a target and scope can never approve their own request. An independent security officer must review and sign off.
										</p>
									</div>
								</div>

								<div className="flex items-start gap-3">
									<div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5">
										<Terminal className="h-4 w-4" />
									</div>
									<div>
										<h4 className="text-xs font-bold text-foreground">Controlled Tool Sandbox & Audit Ledger</h4>
										<p className="text-xs text-muted-foreground mt-0.5">
											Agents have no raw terminal shell access. All actions execute through typed Model Context Protocol (MCP) tools with append-only tamper-evident audit logging.
										</p>
									</div>
								</div>
							</div>
						</div>

						{/* Visual Scope & Verification Mockup */}
						<div className="bg-card border border-border/60 rounded-2xl p-6 shadow-xl space-y-4 font-mono text-xs">
							<div className="flex items-center justify-between pb-3 border-b border-border/40">
								<div className="flex items-center gap-2">
									<div className="h-3 w-3 rounded-full bg-rose-500/80" />
									<div className="h-3 w-3 rounded-full bg-amber-500/80" />
									<div className="h-3 w-3 rounded-full bg-emerald-500/80" />
									<span className="text-[11px] text-muted-foreground ml-2">ScopeEnforcer Policy Guard</span>
								</div>
								<Badge className="bg-emerald-600/20 text-emerald-400 border-emerald-500/30 text-[10px]">
									ACTIVE ENFORCEMENT
								</Badge>
							</div>

							<div className="space-y-2 text-[11px] bg-muted/40 p-3.5 rounded-xl border border-border/30">
								<div className="text-muted-foreground"># Deterministic Scope Rules</div>
								<div className="text-emerald-400">+ ALLOW host: "127.0.0.1", port: 5000, paths: ["/rest/*", "/api/*"]</div>
								<div className="text-rose-400">- DENY  host: "*", paths: ["/admin/logout", "/payments/*"]</div>
								<div className="text-amber-400">! RULE  excluded_paths strictly override included_paths</div>
							</div>

							<div className="space-y-2 text-[11px] bg-muted/40 p-3.5 rounded-xl border border-border/30">
								<div className="text-muted-foreground"># Cryptographic Verification Evidence</div>
								<div className="text-cyan-400">finding_id: "VULN-001"</div>
								<div className="text-cyan-400">corroborating_invocation: "INV-0005" (probe_bola_idor)</div>
								<div className="text-emerald-400">validator_decision: "VAL-DEC-0001" (CONFIRMED)</div>
								<div className="text-emerald-400">evidence_record: "EVID-0001" (SHA-256 Verified Proof)</div>
								<div className="text-muted-foreground">affected_url: "/rest/basket/2" (Canonical Normalized)</div>
							</div>

							<div className="pt-2 flex items-center justify-between text-[11px] text-muted-foreground">
								<span>Status: Verified Safe & Fully Scoped</span>
								<span className="text-emerald-400 font-bold">100% Deterministic</span>
							</div>
						</div>
					</div>
				</div>
			</section>

			{/* CLOSING CALL TO ACTION */}
			<section className="py-20 sm:py-24 relative overflow-hidden bg-gradient-to-b from-background to-muted/20">
				<div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-6">
					<div className="inline-flex items-center justify-center p-3 rounded-2xl bg-primary/10 border border-primary/20 text-primary shadow-sm mb-2">
						<Shield className="h-8 w-8" />
					</div>

					<h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-foreground">
						Ready to understand your application's security?
					</h2>

					<p className="text-sm sm:text-base text-muted-foreground max-w-xl mx-auto leading-relaxed">
						Experience autonomous multi-agent penetration testing in minutes using our managed practice lab, or connect your external application with verified cryptographic authorization.
					</p>

					<div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-4">
						<Button
							size="lg"
							onClick={onGetStarted}
							className="w-full sm:w-auto gap-2 px-8 py-6 text-sm font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-xl shadow-primary/20"
						>
							Start with VIGIL
							<ArrowRight className="h-4 w-4" />
						</Button>
						<Button
							size="lg"
							variant="outline"
							onClick={onSignIn}
							className="w-full sm:w-auto px-8 py-6 text-sm font-semibold border-border/80"
						>
							Sign In to Console
						</Button>
					</div>
				</div>
			</section>

			{/* FOOTER */}
			<footer className="border-t border-border/40 py-8 bg-card">
				<div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-muted-foreground">
					<div className="flex items-center gap-2">
						<Shield className="h-4 w-4 text-primary" />
						<span className="font-bold text-foreground">VIGIL</span>
						<span>© 2026 Autonomous Security Intelligence. Authorized Testing Only.</span>
					</div>
					<div className="flex items-center gap-6">
						<a href="#capabilities" className="hover:text-foreground transition-colors">
							Capabilities
						</a>
						<a href="#how-it-works" className="hover:text-foreground transition-colors">
							How It Works
						</a>
						<a href="#architecture" className="hover:text-foreground transition-colors">
							Specialist Agents
						</a>
						<a href="#security" className="hover:text-foreground transition-colors">
							Security & Scoping
						</a>
					</div>
				</div>
			</footer>
		</div>
	);
}

