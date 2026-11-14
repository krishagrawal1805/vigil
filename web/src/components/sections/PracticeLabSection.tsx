import React from "react";
import {
	Server,
	Play,
	Square,
	RefreshCw,
	Copy,
	Check,
	ExternalLink,
	Shield,
	Lock,
	Clock,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { LabSession } from "@/store";

interface PracticeLabSectionProps {
	managedLabs?: LabSession[];
	labDuration: number;
	setLabDuration: (duration: number) => void;
	onStartLab: () => void;
	isStartingLab: boolean;
	onStopLab: (labId: string) => void;
	isStoppingLab: boolean;
	onStartAssessment: (grantId?: string) => void;
	copiedTarget: boolean;
	onCopy: (text: string) => void;
	renderStatusBadge: (status: string) => React.ReactNode;
}

export function PracticeLabSection({
	managedLabs,
	labDuration,
	setLabDuration,
	onStartLab,
	isStartingLab,
	onStopLab,
	isStoppingLab,
	onStartAssessment,
	copiedTarget,
	onCopy,
	renderStatusBadge,
}: PracticeLabSectionProps) {
	const activeLab = managedLabs?.find((l) => l.status === "running");

	return (
		<div className="space-y-6">
			<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
				{/* Target Spec & Launch Card */}
				<Card className="lg:col-span-1">
					<CardHeader>
						<div className="flex items-center justify-between">
							<CardTitle className="text-base">Practice Target</CardTitle>
							<Badge variant="secondary">OWASP Juice Shop / Mock</Badge>
						</div>
						<CardDescription>
							Intentionally vulnerable target pinned to port 5000 with deterministic ScopeEnforcer bounds.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4 text-xs">
						<div className="space-y-2 border rounded-lg p-3 bg-muted/20">
							<div className="flex justify-between">
								<span className="text-muted-foreground">Target Port:</span>
								<span className="font-mono font-semibold">5000</span>
							</div>
							<div className="flex justify-between">
								<span className="text-muted-foreground">Loopback Binding:</span>
								<span className="font-mono text-[11px]">127.0.0.1:5000</span>
							</div>
							<div className="flex justify-between">
								<span className="text-muted-foreground">Legacy Port 3000:</span>
								<span className="text-emerald-600 font-semibold">Disabled (Dedicated to Web UI)</span>
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
								Target environment is automatically destroyed and authorization grants revoked upon expiration.
							</p>
						</div>
					</CardContent>
					<CardFooter>
						<Button
							onClick={onStartLab}
							disabled={isStartingLab || !!activeLab}
							className="w-full gap-2"
						>
							{isStartingLab ? (
								<>
									<RefreshCw className="h-4 w-4 animate-spin" />
									Provisioning Target...
								</>
							) : (
								<>
									<Play className="h-4 w-4" />
									{activeLab ? "Practice Lab Already Active" : "Launch Practice Lab"}
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
										<div className="text-xs text-muted-foreground font-medium">Friendly Target Name</div>
										<div className="text-sm font-semibold text-foreground mt-0.5">
											OWASP Juice Shop — Managed Practice Lab
										</div>
										<div className="text-xs text-muted-foreground font-medium mt-2">Browser-Accessible Target URL</div>
										<div className="text-base font-mono font-bold text-primary mt-0.5">
											{activeLab.browser_url || activeLab.browser_target_url || "http://127.0.0.1:5000"}
										</div>
										<details className="mt-2 text-[10px] text-muted-foreground font-mono cursor-pointer">
											<summary className="hover:text-foreground">Technical Details: Internal Docker Target</summary>
											<div className="mt-1 p-1.5 rounded bg-muted/40 border border-border/40">
												Internal Agent Target: <span className="font-semibold text-foreground">{activeLab.target_url}</span>
											</div>
										</details>
									</div>
									<div className="flex items-center gap-2">
										<Button
											variant="outline"
											size="sm"
											onClick={() => onCopy(activeLab.browser_url || activeLab.browser_target_url || "http://127.0.0.1:5000")}
											className="gap-1.5 text-xs"
										>
											{copiedTarget ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
											{copiedTarget ? "Copied" : "Copy URL"}
										</Button>
										<Button
											variant="secondary"
											size="sm"
											asChild
											className="gap-1.5 text-xs"
										>
											<a href={activeLab.browser_url || activeLab.browser_target_url || "http://127.0.0.1:5000"} target="_blank" rel="noopener noreferrer">
												<ExternalLink className="h-3.5 w-3.5" />
												Open Target
											</a>
										</Button>
									</div>
								</div>

								{/* Session Metadata Grid */}
								<div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
									<div className="border rounded-md p-2.5 bg-card">
										<div className="text-muted-foreground">Lab Instance</div>
										<div className="font-mono font-semibold truncate mt-0.5">{activeLab.lab_instance_id}</div>
									</div>
									<div className="border rounded-md p-2.5 bg-card">
										<div className="text-muted-foreground">Container / PID</div>
										<div className="font-mono font-semibold truncate mt-0.5">{activeLab.container_id}</div>
									</div>
									<div className="border rounded-md p-2.5 bg-card">
										<div className="text-muted-foreground">Associated Grant</div>
										<div className="font-mono font-semibold truncate mt-0.5">{activeLab.grant_id}</div>
									</div>
									<div className="border rounded-md p-2.5 bg-card">
										<div className="text-muted-foreground">Assessment Window</div>
										<div className="font-mono font-semibold truncate mt-0.5 flex items-center gap-1">
											<Clock className="h-3 w-3 text-primary" />
											{new Date(activeLab.expires_at).toLocaleTimeString()}
										</div>
									</div>
								</div>

								{/* Scope Policy Details */}
								<div className="p-3.5 rounded-lg border bg-card space-y-2 text-xs">
									<div className="font-semibold text-foreground flex items-center gap-1.5">
										<Shield className="h-4 w-4 text-emerald-600" />
										Active Scope Policy (Deterministic Grant Enforcement)
									</div>
									<div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
										<div>
											<span className="font-medium text-muted-foreground">Allowed CIDRs:</span>
											<span className="font-mono ml-1.5 text-foreground">127.0.0.1/32, 172.28.0.0/16</span>
										</div>
										<div>
											<span className="font-medium text-muted-foreground">Allowed Ports:</span>
											<span className="font-mono ml-1.5 text-foreground">5000</span>
										</div>
										<div>
											<span className="font-medium text-muted-foreground">Allowed Methods:</span>
											<span className="font-mono ml-1.5 text-foreground">GET, POST, PUT, DELETE, PATCH, HEAD</span>
										</div>
										<div>
											<span className="font-medium text-muted-foreground">Revocation Policy:</span>
											<span className="font-mono ml-1.5 text-emerald-600">Immediate Egress Drop on Revocation</span>
										</div>
									</div>
								</div>

								{/* Action Buttons */}
								<div className="flex items-center justify-end gap-3 pt-2">
									<Button
										variant="destructive"
										size="sm"
										onClick={() => onStopLab(activeLab.lab_instance_id)}
										disabled={isStoppingLab}
										className="gap-1.5 text-xs"
									>
										<Square className="h-3.5 w-3.5" />
										Stop Practice Lab
									</Button>
									<Button
										variant="default"
										size="sm"
										onClick={() => onStartAssessment(activeLab.grant_id)}
										className="gap-1.5 text-xs"
									>
										<Play className="h-3.5 w-3.5" />
										Launch Autonomous Pentest
									</Button>
								</div>
							</div>
						) : (
							<div className="text-center py-12 text-muted-foreground text-sm space-y-3">
								<Server className="h-10 w-10 mx-auto text-muted-foreground/40" />
								<p>No managed practice lab is currently running.</p>
								<p className="text-xs max-w-md mx-auto">
									Click "Launch Practice Lab" to spin up an isolated testing environment on port 5000.
								</p>
							</div>
						)}
					</CardContent>
				</Card>
			</div>
		</div>
	);
}

