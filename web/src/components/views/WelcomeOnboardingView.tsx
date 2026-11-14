import React from "react";
import {
	Server,
	Globe,
	ArrowRight,
	CheckCircle2,
	Play,
	Shield,
	FileText,
	Loader2,
	Lock,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { LabSession } from "@/store";

interface WelcomeOnboardingViewProps {
	onStartPracticeLab: () => void;
	onStartExternal: () => void;
	onReviewFindings: () => void;
	onSkipToDashboard?: () => void;
	isStartingPractice?: boolean;
	managedLabs?: LabSession[];
}

export function WelcomeOnboardingView({
	onStartPracticeLab,
	onStartExternal,
	onReviewFindings,
	onSkipToDashboard,
	isStartingPractice = false,
	managedLabs,
}: WelcomeOnboardingViewProps) {
	const activeLab = managedLabs?.find((l) => l.status === "running");

	return (
		<div className="max-w-4xl mx-auto py-8 sm:py-12 space-y-8 animate-in fade-in duration-200">
			{/* Clean, Direct Header */}
			<div className="text-center space-y-2">
				<div className="inline-flex items-center justify-center p-2.5 rounded-xl bg-blue-50 border border-blue-200 text-blue-600 mb-1">
					<Shield className="h-7 w-7 text-blue-600" />
				</div>
				<h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900">
					Select a Test Category
				</h1>
				<p className="text-xs sm:text-sm text-slate-600 max-w-lg mx-auto">
					Choose an assessment category to begin your autonomous security test.
				</p>
			</div>

			{/* Exactly 2 Clean, Distinct Primary Assessment Categories */}
			<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
				{/* CATEGORY 1: PRACTICE ASSESSMENT (OWASP JUICE SHOP) */}
				<Card className="relative flex flex-col justify-between border-2 border-emerald-500/60 bg-white hover:border-emerald-600 hover:shadow-lg transition-all shadow-xs ring-1 ring-emerald-500/20 group">
					<div className="absolute -top-3 left-6">
						<Badge className="bg-emerald-600 hover:bg-emerald-600 text-white border-0 text-[10px] font-bold px-2.5 py-0.5 shadow-xs">
							RECOMMENDED FOR DEMOS
						</Badge>
					</div>

					<CardHeader className="pt-7 pb-2 space-y-2.5">
						<div className="flex items-center justify-between">
							<div className="h-11 w-11 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
								<Server className="h-5 w-5" />
							</div>
							<Badge
								variant="outline"
								className="text-[10px] font-bold text-emerald-700 border-emerald-300 bg-emerald-50"
							>
								{activeLab ? "ONLINE (PORT 5000)" : "1-CLICK LAUNCH"}
							</Badge>
						</div>
						<div>
							<CardTitle className="text-lg font-bold text-slate-900">
								Practice Assessment
							</CardTitle>
							<div className="text-xs font-medium text-slate-500 mt-0.5">
								OWASP Juice Shop Managed Sandbox
							</div>
						</div>
						<CardDescription className="text-xs text-slate-600 leading-relaxed">
							Test the managed OWASP Juice Shop environment safely in an isolated Docker sandbox with zero setup.
						</CardDescription>
					</CardHeader>

					<CardContent className="space-y-3 pb-4">
						<div className="space-y-2 text-xs text-slate-600 border-t border-slate-100 pt-3">
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 flex-shrink-0" />
								<span>Pre-configured target on port 5000</span>
							</div>
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 flex-shrink-0" />
								<span>Autonomous BOLA, SQLi & XSS testing</span>
							</div>
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 flex-shrink-0" />
								<span>Independent exploit proof validation</span>
							</div>
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 flex-shrink-0" />
								<span>Live Split-Screen Demonstration Mode</span>
							</div>
						</div>
					</CardContent>

					<CardFooter className="pt-0">
						<Button
							onClick={onStartPracticeLab}
							disabled={isStartingPractice}
							className="w-full justify-between gap-2 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs shadow-xs py-5"
						>
							<span className="flex items-center gap-2">
								{isStartingPractice ? (
									<Loader2 className="h-4 w-4 animate-spin" />
								) : (
									<Play className="h-4 w-4" />
								)}
								<span>{isStartingPractice ? "Launching Practice Test..." : "Start Practice Assessment"}</span>
							</span>
							<ArrowRight className="h-4 w-4 opacity-75" />
						</Button>
					</CardFooter>
				</Card>

				{/* CATEGORY 2: EXTERNAL WEB APPLICATION ASSESSMENT */}
				<Card className="flex flex-col justify-between border-2 border-slate-200 bg-white hover:border-blue-500 hover:shadow-lg transition-all shadow-xs group">
					<CardHeader className="pt-7 pb-2 space-y-2.5">
						<div className="flex items-center justify-between">
							<div className="h-11 w-11 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
								<Globe className="h-5 w-5" />
							</div>
							<Badge
								variant="outline"
								className="text-[10px] font-bold text-blue-700 border-blue-300 bg-blue-50"
							>
								ENTERPRISE
							</Badge>
						</div>
						<div>
							<CardTitle className="text-lg font-bold text-slate-900">
								Web Application Pentest
							</CardTitle>
							<div className="text-xs font-medium text-slate-500 mt-0.5">
								External Attack Surface
							</div>
						</div>
						<CardDescription className="text-xs text-slate-600 leading-relaxed">
							Assess an external web application or domain you own or have explicit authorization to test.
						</CardDescription>
					</CardHeader>

					<CardContent className="space-y-3 pb-4">
						<div className="space-y-2 text-xs text-slate-600 border-t border-slate-100 pt-3">
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-blue-600 flex-shrink-0" />
								<span>Bring any custom target URL or API</span>
							</div>
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-blue-600 flex-shrink-0" />
								<span>Autonomous discovery & OWASP Top 10 probing</span>
							</div>
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-blue-600 flex-shrink-0" />
								<span>Instant 1-click authorization certification</span>
							</div>
							<div className="flex items-center gap-2">
								<CheckCircle2 className="h-3.5 w-3.5 text-blue-600 flex-shrink-0" />
								<span>Executive & technical vulnerability reports</span>
							</div>
						</div>
					</CardContent>

					<CardFooter className="pt-0">
						<Button
							variant="outline"
							onClick={onStartExternal}
							className="w-full justify-between gap-2 border-slate-300 hover:border-blue-500 hover:text-blue-600 font-semibold text-xs py-5"
						>
							<span className="flex items-center gap-2">
								<Globe className="h-4 w-4" />
								<span>Start Web Pentest</span>
							</span>
							<ArrowRight className="h-4 w-4 opacity-75" />
						</Button>
					</CardFooter>
				</Card>
			</div>

			{/* Subdued Bottom Navigation for Previous Results */}
			<div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
				<div className="flex items-center gap-2">
					<FileText className="h-4 w-4 text-slate-500" />
					<span>Need to review past assessment findings or download reports?</span>
				</div>
				<div className="flex items-center gap-3">
					<button
						onClick={onReviewFindings}
						className="font-semibold text-blue-600 hover:text-blue-800 hover:underline inline-flex items-center gap-1"
					>
						View Results & Reports →
					</button>
					{onSkipToDashboard && (
						<>
							<span className="text-slate-300">•</span>
							<button
								onClick={onSkipToDashboard}
								className="text-slate-500 hover:text-slate-800 hover:underline"
							>
								Operations Dashboard
							</button>
						</>
					)}
				</div>
			</div>
		</div>
	);
}
