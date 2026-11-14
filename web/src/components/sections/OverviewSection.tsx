import React from "react";
import {
	Server,
	Globe,
	ShieldAlert,
	Ban,
	Shield,
	Cpu,
	Lock,
	HardDrive,
	Play,
	Square,
	Copy,
	Check,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
	LabSession,
	AuthorizationGrant,
	AssessmentResultsResponse,
} from "@/store";

interface OverviewSectionProps {
	managedLabs?: LabSession[];
	externalGrants?: AuthorizationGrant[];
	assessmentResults?: AssessmentResultsResponse;
	onNavigateTab: (tab: string) => void;
	onStartAssessment: (grantId?: string) => void;
	onStopLab: (labId: string) => void;
	isStoppingLab: boolean;
	copiedTarget: boolean;
	onCopy: (text: string) => void;
	renderStatusBadge: (status: string) => React.ReactNode;
}

export function OverviewSection({
	managedLabs,
	externalGrants,
	assessmentResults,
	onNavigateTab,
	onStartAssessment,
	onStopLab,
	isStoppingLab,
	copiedTarget,
	onCopy,
	renderStatusBadge,
}: OverviewSectionProps) {
	return (
		<div className="space-y-6">
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
						<p className="text-xs text-muted-foreground mt-1">Active isolated target containers</p>
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
							<CardTitle className="text-base font-semibold">Deterministic Scope Enforcement</CardTitle>
						</div>
						<Badge className="bg-emerald-600 text-white font-mono text-xs">SCOPE_ENFORCER_ACTIVE</Badge>
					</div>
					<CardDescription>
						Every outbound HTTP request is cryptographically checked against authorization grants before transmission.
					</CardDescription>
				</CardHeader>
				<CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
					<div className="p-3 rounded-lg border bg-card space-y-1">
						<div className="font-semibold text-foreground flex items-center gap-1.5">
							<Cpu className="h-3.5 w-3.5 text-primary" />
							Target Egress Isolation
						</div>
						<p className="text-muted-foreground">
							Containers run on isolated bridge (<span className="font-mono">VIGIL-lab-net</span>). WAN default routes are stripped; outbound metadata is unreachable.
						</p>
					</div>

					<div className="p-3 rounded-lg border bg-card space-y-1">
						<div className="font-semibold text-foreground flex items-center gap-1.5">
							<Lock className="h-3.5 w-3.5 text-primary" />
							Grant Bound Verification
						</div>
						<p className="text-muted-foreground">
							Grants bind to exact TargetHost, Port, Allowed Paths, and Methods. Client-side grant minting is forbidden.
						</p>
					</div>

					<div className="p-3 rounded-lg border bg-card space-y-1">
						<div className="font-semibold text-foreground flex items-center gap-1.5">
							<HardDrive className="h-3.5 w-3.5 text-primary" />
							Resource Caps & Janitor
						</div>
						<p className="text-muted-foreground">
							Practice lab containers are capped at 512MB RAM, 1.0 CPU, 200 PIDs. Background janitor auto-destroys expired sessions.
						</p>
					</div>
				</CardContent>
			</Card>

			{/* Active Practice Labs Quick Table */}
			<Card>
				<CardHeader className="flex flex-row items-center justify-between">
					<div>
						<CardTitle className="text-base">Managed Practice Labs</CardTitle>
						<CardDescription>Currently running intentionally vulnerable target environments</CardDescription>
					</div>
					<Button size="sm" onClick={() => onNavigateTab("practice-lab")} className="gap-1.5">
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
											<div className="flex flex-col gap-0.5 font-mono text-xs">
												<div className="flex items-center gap-1.5">
													<a
														href={lab.browser_url || lab.browser_target_url || "http://127.0.0.1:5000"}
														target="_blank"
														rel="noopener noreferrer"
														className="text-primary hover:underline font-semibold"
													>
														{lab.browser_url || lab.browser_target_url || "http://127.0.0.1:5000"}
													</a>
													<button
														onClick={() => onCopy(lab.browser_url || lab.browser_target_url || "http://127.0.0.1:5000")}
														className="text-muted-foreground hover:text-foreground cursor-pointer"
														title="Copy Browser URL"
													>
														{copiedTarget ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
													</button>
												</div>
												<span className="text-[10px] text-muted-foreground">Internal: {lab.target_url}</span>
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
														onClick={() => onStartAssessment(lab.grant_id)}
														className="gap-1 text-xs"
													>
														<Play className="h-3 w-3" />
														Run Pentest
													</Button>
													<Button
														variant="outline"
														size="sm"
														onClick={() => onStopLab(lab.lab_instance_id)}
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
							No practice labs currently running. Launch a practice lab from the Practice Lab tab.
						</div>
					)}
				</CardContent>
			</Card>
		</div>
	);
}

