import React, { useState } from "react";
import { ExternalLink, ChevronDown, ChevronUp, Server, Globe } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface TargetDisplayProps {
	target?: string;
	className?: string;
	compact?: boolean;
	showLink?: boolean;
}

export function TargetDisplay({
	target = "",
	className = "",
	compact = false,
	showLink = true,
}: TargetDisplayProps) {
	const [showInternal, setShowInternal] = useState(false);

	const isPracticeLab =
		target.includes("platform-practice-lab") ||
		target.includes("127.0.0.1:5000") ||
		target.includes("localhost:5000") ||
		target.includes(":5000") ||
		target.includes(":3000");

	if (!target) {
		return <span className={`text-muted-foreground ${className}`}>No target selected</span>;
	}

	if (isPracticeLab) {
		const browserUrl = "http://127.0.0.1:5000";
		const internalDockerUrl = "http://platform-practice-lab:3000";

		if (compact) {
			return (
				<span className={`inline-flex items-center gap-1.5 flex-wrap ${className}`}>
					<span className="font-semibold text-foreground">
						OWASP Juice Shop — Managed Practice Lab
					</span>
					{showLink && (
						<a
							href={browserUrl}
							target="_blank"
							rel="noopener noreferrer"
							className="text-primary hover:underline font-mono text-[11px] inline-flex items-center gap-0.5 ml-1"
							title="Open lab in browser (127.0.0.1:5000)"
						>
							{browserUrl}
							<ExternalLink className="h-3 w-3 inline" />
						</a>
					)}
				</span>
			);
		}

		return (
			<div className={`space-y-1.5 ${className}`}>
				<div className="flex flex-wrap items-center gap-2">
					<span className="font-semibold text-foreground flex items-center gap-1.5 text-xs">
						<Server className="h-3.5 w-3.5 text-primary" />
						OWASP Juice Shop — Managed Practice Lab
					</span>
					{showLink && (
						<a
							href={browserUrl}
							target="_blank"
							rel="noopener noreferrer"
							className="text-primary hover:underline font-mono text-xs font-semibold inline-flex items-center gap-1 bg-primary/10 px-2 py-0.5 rounded border border-primary/20"
							title="Open browser-accessible lab"
						>
							{browserUrl}
							<ExternalLink className="h-3 w-3" />
						</a>
					)}
				</div>
				<div>
					<button
						type="button"
						onClick={() => setShowInternal(!showInternal)}
						className="text-[10px] text-muted-foreground hover:text-foreground font-mono flex items-center gap-1 transition-colors"
					>
						<span>Technical Details: Internal Docker Target</span>
						{showInternal ? <ChevronUp className="h-2.5 w-2.5" /> : <ChevronDown className="h-2.5 w-2.5" />}
					</button>
					{showInternal && (
						<div className="mt-1 p-2 rounded bg-muted/30 border border-border/40 font-mono text-[10px] text-muted-foreground space-y-0.5">
							<div>
								Agent & Controlled MCP Target: <span className="text-foreground font-semibold">{internalDockerUrl}</span>
							</div>
							<div>
								Docker Network: <span className="text-foreground">lab-net (bridge isolation)</span>
							</div>
						</div>
					)}
				</div>
			</div>
		);
	}

	// External authorized target
	return (
		<span className={`inline-flex items-center gap-1.5 ${className}`}>
			<Globe className="h-3.5 w-3.5 text-primary" />
			<span className="font-mono text-xs text-foreground">{target}</span>
		</span>
	);
}

