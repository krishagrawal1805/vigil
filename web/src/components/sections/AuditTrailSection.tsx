import React, { useState } from "react";
import {
	Terminal,
	Shield,
	RefreshCw,
	Search,
	CheckCircle2,
	Lock,
	ChevronDown,
	ChevronUp,
	Copy,
	Check,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AuditEvent } from "@/store";

interface AuditTrailSectionProps {
	auditEvents?: AuditEvent[];
	isLoading: boolean;
	onRefresh: () => void;
}

export function AuditTrailSection({
	auditEvents,
	isLoading,
	onRefresh,
}: AuditTrailSectionProps) {
	const [searchTerm, setSearchTerm] = useState("");
	const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});
	const [copiedId, setCopiedId] = useState<string | null>(null);

	const toggleRow = (id: string) => {
		setExpandedRows((prev) => ({
			...prev,
			[id]: !prev[id],
		}));
	};

	const handleCopy = (id: string, text: string) => {
		navigator.clipboard.writeText(text);
		setCopiedId(id);
		setTimeout(() => setCopiedId(null), 2000);
	};

	const filteredEvents = (auditEvents || []).filter((e) => {
		if (!searchTerm.trim()) return true;
		const s = searchTerm.toLowerCase();
		return (
			e.event_type.toLowerCase().includes(s) ||
			e.user_id.toLowerCase().includes(s) ||
			e.org_id.toLowerCase().includes(s) ||
			e.details.toLowerCase().includes(s)
		);
	});

	const eventBadge = (type: string) => {
		switch (type) {
			case "USER_LOGIN":
			case "DNS_VERIFIED":
			case "ASSESSMENT_APPROVED":
				return <Badge className="bg-emerald-600 text-white text-[10px]">{type}</Badge>;
			case "USER_LOGOUT":
			case "GRANT_REVOKED":
				return <Badge variant="secondary" className="text-[10px]">{type}</Badge>;
			case "CROSS_TENANT_ATTEMPT":
			case "TWO_PERSON_VIOLATION":
			case "SCOPE_VIOLATION":
				return <Badge className="bg-rose-600 text-white text-[10px]">{type}</Badge>;
			case "ADMIN_CROSS_TENANT_ACCESS":
				return <Badge className="bg-amber-600 text-white text-[10px]">{type}</Badge>;
			default:
				return <Badge variant="outline" className="text-[10px]">{type}</Badge>;
		}
	};

	return (
		<div className="space-y-6">
			<Card className="border-border/60">
				<CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3">
					<div>
						<div className="flex items-center gap-2">
							<Terminal className="h-5 w-5 text-primary" />
							<CardTitle className="text-base font-semibold">Cryptographic Audit Trail</CardTitle>
						</div>
						<CardDescription className="text-xs">
							Immutable, server-logged operational and security decisions with operator provenance.
						</CardDescription>
					</div>

					<div className="flex items-center gap-2">
						<div className="relative w-64">
							<Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
							<Input
								placeholder="Filter audit events..."
								value={searchTerm}
								onChange={(e) => setSearchTerm(e.target.value)}
								className="pl-8 h-8 text-xs bg-muted/20"
							/>
						</div>
						<Button
							variant="outline"
							size="sm"
							onClick={onRefresh}
							disabled={isLoading}
							className="h-8 gap-1.5 text-xs"
						>
							<RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
							Refresh
						</Button>
					</div>
				</CardHeader>
				<CardContent>
					{filteredEvents.length > 0 ? (
						<div className="w-full overflow-x-auto">
							<Table className="w-full">
								<TableHeader>
									<TableRow className="bg-muted/30">
										<TableHead className="text-xs font-semibold w-44">Timestamp</TableHead>
										<TableHead className="text-xs font-semibold w-36">Event Type</TableHead>
										<TableHead className="text-xs font-semibold w-28">Actor</TableHead>
										<TableHead className="text-xs font-semibold w-28">Organization</TableHead>
										<TableHead className="text-xs font-semibold">Cryptographic Details</TableHead>
									</TableRow>
								</TableHeader>
								<TableBody>
									{filteredEvents.map((evt, idx) => {
										const rowKey = evt.id || `evt-${idx}`;
										const isExpanded = !!expandedRows[rowKey];
										const isLong = evt.details && evt.details.length > 90;

										return (
											<TableRow key={rowKey} className="hover:bg-muted/10">
												<TableCell className="font-mono text-[11px] text-muted-foreground whitespace-nowrap align-top py-3">
													{new Date(evt.timestamp).toLocaleString()}
												</TableCell>
												<TableCell className="align-top py-3">
													{eventBadge(evt.event_type)}
												</TableCell>
												<TableCell className="font-mono text-xs font-semibold text-foreground align-top py-3">
													{evt.user_id}
												</TableCell>
												<TableCell className="font-mono text-xs text-muted-foreground align-top py-3">
													{evt.org_id}
												</TableCell>
												<TableCell className="text-xs font-mono text-foreground leading-normal align-top py-3">
													<div className="whitespace-normal break-words max-w-xl">
														{!isExpanded && isLong ? (
															<div>
																<span>{evt.details.substring(0, 85)}...</span>
																<button
																	type="button"
																	onClick={() => toggleRow(rowKey)}
																	className="text-primary hover:underline ml-1.5 font-sans font-semibold text-[11px] inline-flex items-center gap-0.5"
																>
																	<span>Expand details</span>
																	<ChevronDown className="h-2.5 w-2.5" />
																</button>
															</div>
														) : (
															<div className="space-y-2">
																<div className={isLong ? "p-2.5 rounded bg-black/40 border border-border/40 text-emerald-300 font-mono text-[11px]" : ""}>
																	{evt.details}
																</div>
																{isLong && (
																	<div className="flex items-center gap-3 font-sans">
																		<button
																			type="button"
																			onClick={() => toggleRow(rowKey)}
																			className="text-primary hover:underline text-[11px] font-semibold inline-flex items-center gap-0.5"
																		>
																			<span>Collapse details</span>
																			<ChevronUp className="h-2.5 w-2.5" />
																		</button>
																		<button
																			type="button"
																			onClick={() => handleCopy(rowKey, evt.details)}
																			className="text-muted-foreground hover:text-foreground text-[10px] inline-flex items-center gap-1"
																		>
																			{copiedId === rowKey ? (
																				<Check className="h-3 w-3 text-emerald-400" />
																			) : (
																				<Copy className="h-3 w-3" />
																			)}
																			<span>{copiedId === rowKey ? "Copied" : "Copy details"}</span>
																		</button>
																	</div>
																)}
															</div>
														)}
													</div>
												</TableCell>
											</TableRow>
										);
									})}
								</TableBody>
							</Table>
						</div>
					) : (
						<div className="text-center py-10 text-muted-foreground text-sm space-y-2">
							<Lock className="h-8 w-8 mx-auto text-muted-foreground/40" />
							<p>No audit events match current filter.</p>
						</div>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
