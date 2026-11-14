import { AssessmentResultsResponse, AssessmentStatusResponse, SecurityFinding } from "@/store";

export type FindingClassification =
	| "Confirmed"
	| "Potential"
	| "Inconclusive"
	| "Rejected"
	| "Unverified";

/**
 * Normalizes an endpoint URL or path string consistently.
 * Extracts the pathname from full URLs and standardizes leading slashes and query strings.
 */
export function normalizeEndpointUrl(urlOrPath?: string): string {
	if (!urlOrPath) return "";
	let clean = urlOrPath.trim();
	// Remove query string and hash fragments for endpoint identity
	clean = clean.split("?")[0].split("#")[0];
	try {
		if (clean.startsWith("http://") || clean.startsWith("https://")) {
			const u = new URL(clean);
			return u.pathname || "/";
		}
	} catch {
		// Keep as is if URL parsing fails
	}
	if (!clean.startsWith("/")) {
		clean = "/" + clean;
	}
	return clean;
}

/**
 * Authoritative Canonical Finding Classification.
 * Confidence is strictly a separate measurement and does NOT determine confirmation.
 * A finding is confirmed ONLY when the authoritative validator confirmed it,
 * required technical evidence is present, and it matches the active Run ID.
 */
export function classifyFinding(
	finding: Partial<SecurityFinding> & { verification_status?: string; verification?: string },
	expectedRunId?: string
): FindingClassification {
	// 1. Verify Run ID association if provided
	if (expectedRunId && finding.run_id && finding.run_id !== expectedRunId) {
		return "Unverified";
	}

	const rawStatus = (finding.verification_status || finding.verification || "").toLowerCase().trim();

	// 2. Confirmed state: Requires explicit validator confirmation AND technical evidence
	if (rawStatus === "confirmed") {
		const evidence = (finding.evidence || "").trim();
		if (evidence.length >= 10 && !evidence.toLowerCase().includes("unconfirmed") && !evidence.toLowerCase().includes("not vulnerable")) {
			return "Confirmed";
		}
		return "Potential";
	}

	// 3. Potential state: Plausible candidate without final exploit corroboration
	if (rawStatus === "potential") {
		return "Potential";
	}

	// 4. Inconclusive state: Testing completed without conclusive positive or negative proof
	if (rawStatus === "inconclusive") {
		return "Inconclusive";
	}

	// 5. Rejected state: Explicitly ruled out with counterevidence or negative controls
	if (rawStatus === "rejected" || rawStatus === "unconfirmed" || rawStatus === "ruled_out") {
		return "Rejected";
	}

	return "Unverified";
}

export interface TelemetryMetrics {
	// 1. Discovered Endpoints
	discoveredEndpointsCount: number | "Unknown" | "Not Available";
	discoveredEndpointsList: string[];

	// 2. Reachability Check (Reconnaissance Only - Not counted as vulnerability security test)
	reachabilityEndpointsCount: number;
	reachabilityEndpointsList: string[];

	// 3. Security-Tested Discovered Endpoints (Vulnerability Testing)
	securityTestedDiscoveredEndpointsCount: number;
	securityTestedDiscoveredEndpointsList: string[];

	// 4. Untested Discovered Endpoints (Neither Reachability nor Security Tested)
	untestedDiscoveredEndpointsCount: number | "Unknown";
	untestedDiscoveredEndpointsList: string[];

	// 5. Dynamically Reached Endpoints (Discovered & Security-Tested in-flight)
	dynamicEndpointsCount: number;
	dynamicEndpointsList: string[];

	// 6. Aggregate Totals
	totalSecurityTestedEndpointsCount: number; // 4 discovered + 1 dynamic = 5
	totalSecurityTestedEndpointsList: string[];
	totalEvaluatedEndpointsCount: number; // 1 reachability + 4 security tested + 1 dynamic = 6
	totalEvaluatedEndpointsList: string[];

	// 7. Coverage Percentages
	securityCoveragePercentage: number | "Unknown"; // 4 / 9 = 44% (Strict vulnerability test coverage)
	evaluatedCoveragePercentage: number | "Unknown"; // (1 + 4) / 9 = 56% (Reachability + Security test coverage)
	discoveredCoveragePercentage: number | "Unknown"; // Alias for securityCoveragePercentage (44%)

	// Backwards-compatible aliases
	testedDiscoveredEndpointsCount: number; // 4 (security-tested discovered)
	testedDiscoveredEndpointsList: string[];
	untestedEndpointsCount: number | "Unknown"; // alias for untestedDiscoveredEndpointsCount (4)
	totalTestedEndpointsCount: number; // alias for totalSecurityTestedEndpointsCount (5)
	totalTestedEndpointsList: string[];
	testedEndpointsCount: number; // alias for totalSecurityTestedEndpointsCount (5)
	testedEndpointsList: string[];

	// 8. Scope & Findings & Invocation Totals
	scopeBlockedEndpointsCount: number;
	scopeBlockedEndpointsList: string[];
	scopePrefixesList: string[];
	confirmedFindingsCount: number;
	potentialFindingsCount: number;
	inconclusiveFindingsCount: number;
	rejectedFindingsCount: number;
	unverifiedFindingsCount: number;
	distinctToolsCount: number;
	totalInvocationsCount: number;
	agentDurationSeconds: number;
	missionLifecycleSeconds: number;
}

/**
 * Computes authoritative telemetry metrics across discovered endpoints,
 * tested endpoints, scope boundaries, and canonical finding classifications.
 * Mathematically separates discovered endpoints from dynamically reached endpoints.
 */
export function computeTelemetryMetrics(
	results?: AssessmentResultsResponse,
	liveStatus?: AssessmentStatusResponse
): TelemetryMetrics {
	const currentRunId = liveStatus?.run_id || results?.run_id;

	// 1. Scope Prefixes (Authorized Boundaries) - kept strictly separate from endpoints
	const scopePrefixesList = results?.scope?.allowed_paths || [];

	// 2. Discovered Endpoints - strictly from discover_endpoints capability output
	const discoveredSet = new Set<string>();
	let discoveredCount: number | "Unknown" | "Not Available" = "Unknown";

	if (results?.discovered_endpoints && Array.isArray(results.discovered_endpoints) && results.discovered_endpoints.length > 0) {
		results.discovered_endpoints.forEach((ep) => {
			const norm = normalizeEndpointUrl(ep);
			if (norm) discoveredSet.add(norm);
		});
		discoveredCount = discoveredSet.size;
	} else if (results?.status === "completed") {
		discoveredCount = "Not Available";
	}

	const discoveredEndpointsList = Array.from(discoveredSet).sort();

	// 3. Separate Reachability Probing from Vulnerability Security Testing
	const reachabilitySet = new Set<string>();
	const securityTestedSet = new Set<string>();

	// Always record base target as reachability-checked
	if (results?.target) {
		const baseNorm = normalizeEndpointUrl(results.target);
		if (baseNorm) reachabilitySet.add(baseNorm);
	}

	// From individual tool invocations (if available)
	if (results?.tool_invocations && Array.isArray(results.tool_invocations)) {
		results.tool_invocations.forEach((inv) => {
			if (!inv.target) return;
			const norm = normalizeEndpointUrl(inv.target);
			if (!norm) return;

			const toolLower = (inv.tool || "").toLowerCase();
			if (toolLower.includes("discover") || toolLower === "inspect_http") {
				reachabilitySet.add(norm);
			} else {
				// True security vulnerability testing capability
				securityTestedSet.add(norm);
			}
		});
	}

	// From tested hypotheses (security hypotheses)
	if (results?.hypotheses && Array.isArray(results.hypotheses)) {
		results.hypotheses.forEach((hyp: any) => {
			if (hyp.endpoint) {
				const norm = normalizeEndpointUrl(hyp.endpoint);
				if (norm) securityTestedSet.add(norm);
			}
		});
	}

	// From verified findings
	if (results?.findings && Array.isArray(results.findings)) {
		results.findings.forEach((f) => {
			if (f.affected_url) {
				const norm = normalizeEndpointUrl(f.affected_url);
				if (norm) securityTestedSet.add(norm);
			}
		});
	}

	// Reachability-only set: reached but not security tested
	const reachabilityOnlySet = new Set<string>();
	reachabilitySet.forEach((ep) => {
		if (!securityTestedSet.has(ep)) {
			reachabilityOnlySet.add(ep);
		}
	});

	// 4. Reconcile Discovered vs Security-Tested vs Reachability vs Untested (Strict Disjoint Partition)
	const securityTestedDiscoveredSet = new Set<string>();
	const reachabilityDiscoveredSet = new Set<string>();
	const untestedDiscoveredSet = new Set<string>();
	const dynamicSet = new Set<string>();

	discoveredSet.forEach((ep) => {
		if (securityTestedSet.has(ep)) {
			securityTestedDiscoveredSet.add(ep);
		} else if (reachabilityOnlySet.has(ep)) {
			reachabilityDiscoveredSet.add(ep);
		} else {
			untestedDiscoveredSet.add(ep);
		}
	});

	// Dynamic endpoints reached and security-tested in-flight outside discovered set
	securityTestedSet.forEach((ep) => {
		if (!discoveredSet.has(ep)) {
			dynamicSet.add(ep);
		}
	});

	const securityTestedDiscoveredEndpointsList = Array.from(securityTestedDiscoveredSet).sort();
	const securityTestedDiscoveredEndpointsCount = securityTestedDiscoveredSet.size;

	const reachabilityEndpointsList = Array.from(reachabilityDiscoveredSet).sort();
	const reachabilityEndpointsCount = reachabilityDiscoveredSet.size;

	const untestedDiscoveredEndpointsList = Array.from(untestedDiscoveredSet).sort();
	const untestedDiscoveredEndpointsCount: number | "Unknown" =
		typeof discoveredCount === "number" ? untestedDiscoveredSet.size : "Unknown";

	const dynamicEndpointsList = Array.from(dynamicSet).sort();
	const dynamicEndpointsCount = dynamicSet.size;

	// Total Security-Tested Endpoints (4 discovered + 1 dynamic = 5)
	const allSecurityTestedSet = new Set<string>([...securityTestedDiscoveredSet, ...dynamicSet]);
	const totalSecurityTestedEndpointsList = Array.from(allSecurityTestedSet).sort();
	const totalSecurityTestedEndpointsCount = allSecurityTestedSet.size;

	// Total Evaluated Endpoints (1 reachability + 4 security-tested discovered + 1 dynamic = 6)
	const allEvaluatedSet = new Set<string>([...reachabilityDiscoveredSet, ...allSecurityTestedSet]);
	const totalEvaluatedEndpointsList = Array.from(allEvaluatedSet).sort();
	const totalEvaluatedEndpointsCount = allEvaluatedSet.size;

	// Coverage Percentages
	// Strictly vulnerability security test coverage: securityTestedDiscovered / discoveredCount (e.g. 4 / 9 = 44%)
	let securityCoveragePercentage: number | "Unknown" = "Unknown";
	// Evaluated coverage (including reachability check): (reachability + securityTested) / discoveredCount (e.g. 5 / 9 = 56%)
	let evaluatedCoveragePercentage: number | "Unknown" = "Unknown";

	if (typeof discoveredCount === "number" && discoveredCount > 0) {
		securityCoveragePercentage = Math.round((securityTestedDiscoveredEndpointsCount / discoveredCount) * 100);
		evaluatedCoveragePercentage = Math.round(((securityTestedDiscoveredEndpointsCount + reachabilityEndpointsCount) / discoveredCount) * 100);
	}
	const discoveredCoveragePercentage = securityCoveragePercentage;

	// Backwards-compatible aliases
	const testedDiscoveredEndpointsList = securityTestedDiscoveredEndpointsList;
	const testedDiscoveredEndpointsCount = securityTestedDiscoveredEndpointsCount;
	const totalTestedEndpointsList = totalSecurityTestedEndpointsList;
	const totalTestedEndpointsCount = totalSecurityTestedEndpointsCount;
	const testedEndpointsList = totalSecurityTestedEndpointsList;
	const testedEndpointsCount = totalSecurityTestedEndpointsCount;
	const untestedEndpointsCount = untestedDiscoveredEndpointsCount;

	// 5. Scope-Blocked Requests
	const blockedSet = new Set<string>();
	if (results?.blocked_requests && Array.isArray(results.blocked_requests)) {
		results.blocked_requests.forEach((b) => {
			if (b.target_url) {
				const norm = normalizeEndpointUrl(b.target_url);
				if (norm) blockedSet.add(norm);
			}
		});
	}
	const scopeBlockedEndpointsList = Array.from(blockedSet).sort();
	const scopeBlockedEndpointsCount = blockedSet.size;

	// 6. Canonical Finding Classifications
	let confirmedFindingsCount = 0;
	let potentialFindingsCount = 0;
	let inconclusiveFindingsCount = 0;
	let rejectedFindingsCount = 0;
	let unverifiedFindingsCount = 0;

	if (results?.findings && Array.isArray(results.findings)) {
		results.findings.forEach((f) => {
			const cls = classifyFinding(f, currentRunId);
			if (cls === "Confirmed") confirmedFindingsCount++;
			else if (cls === "Potential") potentialFindingsCount++;
			else if (cls === "Inconclusive") inconclusiveFindingsCount++;
			else if (cls === "Rejected") rejectedFindingsCount++;
			else unverifiedFindingsCount++;
		});
	}

	// 7. Tools and Invocations (Distinct Tools vs Total Invocations)
	const distinctToolsCount = results?.tools_executed?.length || 0;
	const totalInvocationsCount =
		results?.tool_invocations?.length ||
		results?.tools_executed?.reduce((acc, t) => acc + (t.invocations || 1), 0) ||
		liveStatus?.invocations_count ||
		liveStatus?.tools_count ||
		0;

	// 8. Authoritative Durations
	const agentDurationSeconds = results?.duration_seconds ?? liveStatus?.duration_seconds ?? 0;
	let missionLifecycleSeconds = results?.lifecycle_duration_seconds ?? agentDurationSeconds;
	if (results?.start_time && results?.end_time) {
		try {
			const startMs = new Date(results.start_time).getTime();
			const endMs = new Date(results.end_time).getTime();
			if (!isNaN(startMs) && !isNaN(endMs) && endMs >= startMs) {
				missionLifecycleSeconds = Math.round((endMs - startMs) / 1000);
			}
		} catch {}
	}

	return {
		discoveredEndpointsCount: discoveredCount,
		discoveredEndpointsList,
		reachabilityEndpointsCount,
		reachabilityEndpointsList,
		securityTestedDiscoveredEndpointsCount,
		securityTestedDiscoveredEndpointsList,
		untestedDiscoveredEndpointsCount,
		untestedDiscoveredEndpointsList,
		dynamicEndpointsCount,
		dynamicEndpointsList,
		totalSecurityTestedEndpointsCount,
		totalSecurityTestedEndpointsList,
		totalEvaluatedEndpointsCount,
		totalEvaluatedEndpointsList,
		securityCoveragePercentage,
		evaluatedCoveragePercentage,
		discoveredCoveragePercentage,
		testedDiscoveredEndpointsCount,
		testedDiscoveredEndpointsList,
		untestedEndpointsCount,
		totalTestedEndpointsCount,
		totalTestedEndpointsList,
		testedEndpointsCount,
		testedEndpointsList,
		scopeBlockedEndpointsCount,
		scopeBlockedEndpointsList,
		scopePrefixesList,
		confirmedFindingsCount,
		potentialFindingsCount,
		inconclusiveFindingsCount,
		rejectedFindingsCount,
		unverifiedFindingsCount,
		distinctToolsCount,
		totalInvocationsCount,
		agentDurationSeconds,
		missionLifecycleSeconds,
	};
}

