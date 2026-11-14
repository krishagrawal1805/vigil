import React, { useState } from "react";
import {
	Globe,
	Lock,
	CheckCircle2,
	Play,
	Ban,
	Copy,
	Check,
	AlertTriangle,
	ShieldAlert,
	ShieldCheck,
	UserCheck,
	Eye,
	XCircle,
	FileCheck,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AuthorizationGrant, CallerProfile } from "@/store";

interface ExternalTargetsSectionProps {
	profile?: CallerProfile;
	externalGrants?: AuthorizationGrant[];
	extHost: string;
	setExtHost: (val: string) => void;
	extPort: number;
	setExtPort: (val: number) => void;
	extAllowedPaths: string;
	setExtAllowedPaths: (val: string) => void;
	extBlockedPaths: string;
	setExtBlockedPaths: (val: string) => void;
	selectedAssessmentId: string;
	setSelectedAssessmentId: (val: string) => void;
	dnsTokenInput: string;
	setDnsTokenInput: (val: string) => void;
	evidenceRef: string;
	setEvidenceRef: (val: string) => void;
	onRegisterExternal: () => void;
	isRegisteringExt: boolean;
	onVerifyDNS: (asmId: string, token: string) => void;
	isVerifyingDNS: boolean;
	onApproveExternal: (asmId: string) => void;
	isApprovingExt: boolean;
	onRevokeGrant: (grantId: string) => void;
	isRevokingGrant: boolean;
	onStartAssessment: (grantId?: string) => void;
	renderStatusBadge: (status: string) => React.ReactNode;
}

export function ExternalTargetsSection({
	profile,
	externalGrants,
	extHost,
	setExtHost,
	extPort,
	setExtPort,
	extAllowedPaths,
	setExtAllowedPaths,
	extBlockedPaths,
	setExtBlockedPaths,
	selectedAssessmentId,
	setSelectedAssessmentId,
	dnsTokenInput,
	setDnsTokenInput,
	evidenceRef,
	setEvidenceRef,
	onRegisterExternal,
	isRegisteringExt,
	onVerifyDNS,
	isVerifyingDNS,
	onApproveExternal,
	isApprovingExt,
	onRevokeGrant,
	isRevokingGrant,
	onStartAssessment,
	renderStatusBadge,
}: ExternalTargetsSectionProps) {
	const [scopeConfirmed, setScopeConfirmed] = useState<boolean>(false);
	const [activeTab, setActiveTab] = useState<"requester" | "approver">("requester");

	const selectedGrant = externalGrants?.find((g) => g.assessment_id === selectedAssessmentId);
	const isRequesterOfSelected = selectedGrant && profile && selectedGrant.user_id === profile.user_id;

	// Check if current user is an authorized approver role (admin, org-admin, or security_officer)
	const isAuthorizedApproverRole =
		profile?.role === "admin" ||
		profile?.role === "org-admin" ||
		profile?.role === "security_officer";

	const pendingGrants = externalGrants?.filter(
		(g) => g.approval_status !== "approved" && g.approval_status !== "revoked"
	) || [];

	return (
		<div className="space-y-6">
			{/* Top Tab Switcher: Requester vs Independent Approver */}
			<div className="flex items-center gap-2 border-b border-border/40 pb-2">
				<button
					onClick={() => setActiveTab("requester")}
					className={`
						px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5
						${activeTab === "requester" ? "bg-primary text-primary-foreground" : "bg-muted/40 text-muted-foreground hover:text-foreground"}
					`}
				>
					<Globe className="h-3.5 w-3.5" />
					Requester: Target Registration & Scope
				</button>
				<button
					onClick={() => setActiveTab("approver")}
					className={`
						px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5
						${activeTab === "approver" ? "bg-primary text-primary-foreground" : "bg-muted/40 text-muted-foreground hover:text-foreground"}
					`}
				>
					<ShieldCheck className="h-3.5 w-3.5" />
					Independent Approver: Verification & Sign-Off ({pendingGrants.length} Pending)
				</button>
			</div>

			{/* WORKFLOW 1: REQUESTER WORKSPACE */}
			{activeTab === "requester" && (
				<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
					{/* Register Form (2 Cols) */}
					<Card className="lg:col-span-2 border-border/60">
						<CardHeader>
							<div className="flex items-center gap-2">
								<Globe className="h-5 w-5 text-primary" />
								<CardTitle className="text-base font-semibold">Register External Target & Define Scope</CardTitle>
							</div>
							<CardDescription className="text-xs">
								Submit target hostname, port, and explicit scope boundaries. Generates cryptographic DNS challenge token.
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-4 text-xs">
							<div className="grid grid-cols-3 gap-3">
								<div className="col-span-2 space-y-1">
									<Label htmlFor="ext-host" className="text-xs font-semibold">
										Target Hostname <span className="text-rose-400">*</span>
									</Label>
									<Input
										id="ext-host"
										placeholder="e.g. staging.example.com"
										value={extHost}
										onChange={(e) => setExtHost(e.target.value)}
										className="text-xs"
									/>
								</div>
								<div className="space-y-1">
									<Label htmlFor="ext-port" className="text-xs font-semibold">Port</Label>
									<Input
										id="ext-port"
										type="number"
										value={extPort}
										onChange={(e) => setExtPort(Number(e.target.value))}
										className="text-xs"
									/>
								</div>
							</div>

							<div className="space-y-1">
								<Label htmlFor="ext-allowed" className="text-xs font-semibold">
									Allowed Scope Paths (Explicit Inclusions) <span className="text-rose-400">*</span>
								</Label>
								<Input
									id="ext-allowed"
									placeholder="e.g. /public/, /api/, /products/"
									value={extAllowedPaths}
									onChange={(e) => setExtAllowedPaths(e.target.value)}
									className="text-xs font-mono"
								/>
								<p className="text-[10px] text-muted-foreground">
									Comma-separated list of URL prefixes the multi-agent system is permitted to evaluate.
								</p>
							</div>

							<div className="space-y-1">
								<Label htmlFor="ext-blocked" className="text-xs font-semibold">
									Strictly Excluded Paths (ScopeEnforcer Boundaries)
								</Label>
								<Input
									id="ext-blocked"
									placeholder="e.g. /admin/, /payments/, /users/private/"
									value={extBlockedPaths}
									onChange={(e) => setExtBlockedPaths(e.target.value)}
									className="text-xs font-mono"
								/>
								<p className="text-[10px] text-muted-foreground">
									Any requests matching these paths are deterministically intercepted before network egress.
								</p>
							</div>

							{/* Mandatory Scope Confirmation Checkbox */}
							<div className="p-3 rounded-lg border border-border/60 bg-muted/20 space-y-2">
								<label className="flex items-start gap-2.5 cursor-pointer">
									<input
										type="checkbox"
										checked={scopeConfirmed}
										onChange={(e) => setScopeConfirmed(e.target.checked)}
										className="mt-0.5 rounded border-border text-primary focus:ring-primary h-4 w-4"
									/>
									<span className="text-xs text-foreground leading-snug">
										<strong>Explicit Scope Authorization:</strong> I confirm that I have legal authorization to test these target assets and that the defined inclusion and exclusion boundaries reflect official engagement rules.
									</span>
								</label>
							</div>
						</CardContent>
						<CardFooter className="flex justify-between items-center border-t border-border/40 pt-4">
							<span className="text-[11px] text-muted-foreground font-mono">
								Requester Identity: {profile?.user_id || "Anonymous"} ({profile?.role || "standard"})
							</span>
							<Button
								onClick={onRegisterExternal}
								disabled={isRegisteringExt || !extHost.trim() || !extAllowedPaths.trim() || !scopeConfirmed}
								className="text-xs gap-1.5 bg-primary text-primary-foreground font-semibold"
							>
								<Globe className="h-4 w-4" />
								Submit Request & Generate DNS Challenge
							</Button>
						</CardFooter>
					</Card>

					{/* Requester Guidance & Status (1 Col) */}
					<div className="space-y-4">
						<Card className="border-border/60 bg-card">
							<CardHeader className="pb-3">
								<CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
									Two-Person Authorization Rule
								</CardTitle>
							</CardHeader>
							<CardContent className="space-y-3 text-xs text-muted-foreground">
								<div className="flex items-start gap-2.5">
									<div className="h-6 w-6 rounded bg-primary/20 text-primary flex items-center justify-center font-bold text-xs shrink-0">
										1
									</div>
									<div>
										<strong className="text-foreground">Submit Target Request:</strong> Provide explicit scope paths and confirm ownership.
									</div>
								</div>
								<div className="flex items-start gap-2.5">
									<div className="h-6 w-6 rounded bg-primary/20 text-primary flex items-center justify-center font-bold text-xs shrink-0">
										2
									</div>
									<div>
										<strong className="text-foreground">Verify DNS Proof:</strong> Publish the generated cryptographic TXT challenge on your DNS host.
									</div>
								</div>
								<div className="flex items-start gap-2.5">
									<div className="h-6 w-6 rounded bg-primary/20 text-primary flex items-center justify-center font-bold text-xs shrink-0">
										3
									</div>
									<div>
										<strong className="text-foreground">Independent Sign-off:</strong> A separate Security Officer or Admin must review evidence and approve. Requesters cannot approve their own requests.
									</div>
								</div>
							</CardContent>
						</Card>
					</div>
				</div>
			)}

			{/* WORKFLOW 2: INDEPENDENT APPROVER WORKSPACE */}
			{activeTab === "approver" && (
				<div className="space-y-6">
					<Card className="border-border/60">
						<CardHeader>
							<div className="flex items-center justify-between">
								<div className="flex items-center gap-2">
									<ShieldCheck className="h-5 w-5 text-emerald-400" />
									<CardTitle className="text-base font-semibold">
										Independent Authorization & Cryptographic Approval
									</CardTitle>
								</div>
								<Badge variant="outline" className="text-xs font-mono">
									Logged Approver: {profile?.user_id} ({profile?.role})
								</Badge>
							</div>
							<CardDescription className="text-xs">
								Review pending external assessment requests, inspect DNS proofs, and record formal approval evidence.
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-5 text-xs">
							{/* Request Selector */}
							<div className="space-y-1.5">
								<Label htmlFor="sel-asm" className="text-xs font-semibold">Select Pending Request for Review</Label>
								<select
									id="sel-asm"
									value={selectedAssessmentId}
									onChange={(e) => {
										setSelectedAssessmentId(e.target.value);
										const sel = externalGrants?.find((g) => g.assessment_id === e.target.value);
										if (sel?.dns_challenge_token) {
											setDnsTokenInput(sel.dns_challenge_token);
										}
									}}
									className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs shadow-sm font-mono"
								>
									<option value="">-- Choose a pending request to inspect --</option>
									{pendingGrants.map((g) => (
										<option key={g.assessment_id} value={g.assessment_id}>
											{g.assessment_id} — {g.authorized_host}:{g.authorized_port} (Requester: {g.user_id}, Status: {g.approval_status})
										</option>
									))}
								</select>
							</div>

							{selectedGrant ? (
								<div className="space-y-4 pt-2 border-t border-border/40">
									{/* Requester Identity & Two-Person Check */}
									{isRequesterOfSelected ? (
										<div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 space-y-1">
											<div className="font-bold flex items-center gap-1.5 text-xs">
												<ShieldAlert className="h-4 w-4 text-rose-400" />
												Two-Person Separation Rule Enforced
											</div>
											<p className="text-[11px] leading-relaxed">
												You submitted this request as <span className="font-mono font-bold text-white">{selectedGrant.user_id}</span>. Under platform security policy, the requester cannot approve their own target authorization grant. An independent approver must review and authorize this assessment.
											</p>
										</div>
									) : (
										<div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-2 text-xs">
											<UserCheck className="h-4 w-4 shrink-0" />
											<span>Two-person separation verified: Requester is <strong className="font-mono">{selectedGrant.user_id}</strong>, Independent Approver is <strong className="font-mono">{profile?.user_id}</strong>.</span>
										</div>
									)}

									{/* Target Scope Summary */}
									<div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 rounded-lg bg-muted/20 border border-border/40 font-mono text-[11px]">
										<div>
											<span className="text-muted-foreground">Target Host:</span>
											<div className="text-foreground font-semibold mt-0.5">{selectedGrant.authorized_host}:{selectedGrant.authorized_port}</div>
										</div>
										<div>
											<span className="text-muted-foreground">Allowed Scope:</span>
											<div className="text-foreground truncate mt-0.5">{selectedGrant.allowed_paths?.join(", ") || "/"}</div>
										</div>
										<div>
											<span className="text-muted-foreground">Excluded Paths:</span>
											<div className="text-foreground truncate mt-0.5">{selectedGrant.blocked_paths?.join(", ") || "None"}</div>
										</div>
									</div>

									{/* Step A: DNS Challenge Verification */}
									<div className="p-3.5 rounded-lg border border-border/60 bg-muted/20 space-y-2">
										<div className="font-semibold text-foreground flex items-center justify-between text-xs">
											<span className="flex items-center gap-1.5">
												<Globe className="h-3.5 w-3.5 text-primary" />
												Step A: Verify DNS TXT Challenge
											</span>
											{selectedGrant.dns_verified ? (
												<Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/30 text-[10px]">
													<CheckCircle2 className="h-2.5 w-2.5 mr-1" />
													DNS Cryptographically Verified
												</Badge>
											) : (
												<Badge variant="outline" className="text-[10px] text-amber-400 border-amber-500/30">
													Pending DNS TXT Proof
												</Badge>
											)}
										</div>
										<div className="flex gap-2">
											<Input
												id="dns-tok"
												placeholder="VIGIL-auth-..."
												value={dnsTokenInput}
												onChange={(e) => setDnsTokenInput(e.target.value)}
												className="font-mono text-xs"
											/>
											<Button
												variant="outline"
												size="sm"
												onClick={() => onVerifyDNS(selectedAssessmentId, dnsTokenInput)}
												disabled={isVerifyingDNS || !selectedAssessmentId || !dnsTokenInput}
												className="text-xs shrink-0"
											>
												Verify DNS
											</Button>
										</div>
									</div>

									{/* Step B: Formal Authorization Evidence (Disabled if requester is self) */}
									{!isRequesterOfSelected && (
										<div className="p-3.5 rounded-lg border border-border/60 bg-muted/20 space-y-2">
											<div className="font-semibold text-foreground flex items-center justify-between text-xs">
												<span className="flex items-center gap-1.5">
													<Lock className="h-3.5 w-3.5 text-primary" />
													Step B: Two-Person Legal Approval & Evidence Reference
												</span>
												<Badge variant="outline" className="text-[10px] text-primary border-primary/30">
													Independent Officer
												</Badge>
											</div>
											<div className="space-y-1">
												<Label htmlFor="ev-ref" className="text-[11px] text-muted-foreground">
													Contract / Engagement Reference ID (Min 8 characters)
												</Label>
												<div className="flex gap-2">
													<Input
														id="ev-ref"
														placeholder="REF-LEGAL-AUTH-SEC-2026-X"
														value={evidenceRef}
														onChange={(e) => setEvidenceRef(e.target.value)}
														className="font-mono text-xs"
													/>
													<Button
														variant="default"
														size="sm"
														onClick={() => onApproveExternal(selectedAssessmentId)}
														disabled={
															isApprovingExt ||
															!selectedAssessmentId ||
															evidenceRef.trim().length < 8 ||
															isRequesterOfSelected
														}
														className="text-xs shrink-0 bg-primary text-primary-foreground font-semibold"
													>
														<ShieldCheck className="h-3.5 w-3.5 mr-1" />
														Approve & Issue Grant
													</Button>
												</div>
											</div>
										</div>
									)}
								</div>
							) : (
								<div className="text-center py-6 text-muted-foreground text-xs">
									Select a pending assessment above to inspect scope and record authorization sign-off.
								</div>
							)}
						</CardContent>
					</Card>
				</div>
			)}

			{/* External Grants Ledger Table */}
			<Card className="border-border/60">
				<CardHeader>
					<CardTitle className="text-base font-semibold">External Authorization Grants Ledger</CardTitle>
					<CardDescription className="text-xs">
						All external assessment grants with cryptographic verification proofs and lifecycle states
					</CardDescription>
				</CardHeader>
				<CardContent>
					{externalGrants && externalGrants.length > 0 ? (
						<Table>
							<TableHeader>
								<TableRow className="bg-muted/30">
									<TableHead className="text-xs">Assessment ID</TableHead>
									<TableHead className="text-xs">Target Host</TableHead>
									<TableHead className="text-xs">Requester</TableHead>
									<TableHead className="text-xs">DNS Proof</TableHead>
									<TableHead className="text-xs">Status</TableHead>
									<TableHead className="text-xs">Approver / Evidence</TableHead>
									<TableHead className="text-xs">Expires</TableHead>
									<TableHead className="text-xs text-right">Actions</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{externalGrants.map((grant) => (
									<TableRow key={grant.assessment_id}>
										<TableCell className="font-mono text-xs font-semibold">{grant.assessment_id}</TableCell>
										<TableCell className="font-mono text-xs">
											{grant.authorized_host}:{grant.authorized_port}
										</TableCell>
										<TableCell className="font-mono text-xs text-muted-foreground">
											{grant.user_id}
										</TableCell>
										<TableCell>
											{grant.dns_verified ? (
												<Badge variant="outline" className="text-emerald-400 border-emerald-500/30 text-[10px]">
													<CheckCircle2 className="h-2.5 w-2.5 mr-1" />
													Verified
												</Badge>
											) : (
												<span className="font-mono text-[10px] text-muted-foreground truncate max-w-[120px] inline-block">
													{grant.dns_challenge_token || "None"}
												</span>
											)}
										</TableCell>
										<TableCell>{renderStatusBadge(grant.approval_status)}</TableCell>
										<TableCell className="text-xs">
											{grant.approval_status === "approved" ? (
												<div>
													<span className="font-semibold text-foreground">{grant.approver_id}</span>
													<p className="font-mono text-[10px] text-muted-foreground truncate max-w-[140px]">
														{grant.auth_evidence_ref}
													</p>
												</div>
											) : (
												<span className="text-muted-foreground italic text-xs">Pending approval</span>
											)}
										</TableCell>
										<TableCell className="text-xs text-muted-foreground">
											{grant.approval_status === "approved"
												? new Date(grant.expiry_time).toLocaleTimeString()
												: "—"}
										</TableCell>
										<TableCell className="text-right space-x-1.5">
											{grant.approval_status === "approved" && !grant.is_revoked && (
												<>
													<Button
														variant="default"
														size="sm"
														onClick={() => onStartAssessment(grant.grant_id)}
														className="text-xs h-7 px-2"
													>
														<Play className="h-3 w-3 mr-1" />
														Pentest
													</Button>
													<Button
														variant="destructive"
														size="sm"
														onClick={() => onRevokeGrant(grant.grant_id)}
														disabled={isRevokingGrant}
														className="text-xs h-7 px-2"
													>
														<Ban className="h-3 w-3 mr-1" />
														Revoke
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
							No external assessments registered yet. Register your first external target above.
						</div>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
