import React from "react";
import {
	LayoutDashboard,
	PlusCircle,
	Activity,
	Bug,
	Network,
	Server,
	Globe,
	FileText,
	ClipboardList,
	Layers,
} from "lucide-react";
import { Button } from "@/components/ui/button";

export type ViewName =
	| "welcome"
	| "dashboard"
	| "assessment-wizard"
	| "external-workflow"
	| "live-assessment"
	| "findings"
	| "attack-path"
	| "practice-lab"
	| "external-targets"
	| "audit";

interface SidebarProps {
	activeView: ViewName;
	activeFindingsSubTab?: string;
	onNavigate: (view: ViewName, subTab?: string) => void;
	hasActiveAssessment: boolean;
	findingsCount: number;
}

interface NavItem {
	view: ViewName;
	subTab?: string;
	icon: React.ReactNode;
	label: string;
	badge?: React.ReactNode;
}

interface NavSection {
	title: string;
	items: NavItem[];
}

export function Sidebar({
	activeView,
	activeFindingsSubTab,
	onNavigate,
	hasActiveAssessment,
	findingsCount,
}: SidebarProps) {
	const navSections: NavSection[] = [
		{
			title: "Overview",
			items: [
				{
					view: "dashboard",
					icon: <LayoutDashboard className="h-4 w-4" />,
					label: "Overview",
				},
			],
		},
		{
			title: "Assessments",
			items: [
				{
					view: "live-assessment",
					icon: <Activity className="h-4 w-4" />,
					label: "Live Assessment",
					badge: hasActiveAssessment ? (
						<span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
					) : undefined,
				},
				{
					view: "findings",
					subTab: "findings",
					icon: <Bug className="h-4 w-4" />,
					label: "Findings",
					badge:
						findingsCount > 0 ? (
							<span className="ml-auto text-[10px] font-bold bg-primary/20 text-primary px-1.5 py-0.2 rounded-full">
								{findingsCount}
							</span>
						) : undefined,
				},
				{
					view: "findings",
					subTab: "coverage",
					icon: <Layers className="h-4 w-4" />,
					label: "Endpoint Coverage",
				},
				{
					view: "findings",
					subTab: "report",
					icon: <FileText className="h-4 w-4" />,
					label: "Reports",
				},
				{
					view: "attack-path",
					icon: <Network className="h-4 w-4" />,
					label: "Activity Map",
				},
			],
		},
		{
			title: "Applications",
			items: [
				{
					view: "practice-lab",
					icon: <Server className="h-4 w-4" />,
					label: "Managed Practice Lab",
				},
				{
					view: "external-targets",
					icon: <Globe className="h-4 w-4" />,
					label: "External Targets",
				},
			],
		},
		{
			title: "Audit Log",
			items: [
				{
					view: "audit",
					icon: <ClipboardList className="h-4 w-4" />,
					label: "Audit Trail",
				},
			],
		},
	];

	return (
		<aside className="w-16 lg:w-60 flex-shrink-0 bg-card border-r border-border/40 flex flex-col py-4 px-2 gap-4">
			{/* Prominent New Assessment CTA Button */}
			<div className="px-1">
				<Button
					onClick={() => onNavigate("welcome")}
					className="w-full justify-center lg:justify-start gap-2.5 bg-primary text-primary-foreground hover:bg-primary/90 text-xs font-semibold py-2 px-3 shadow-sm"
				>
					<PlusCircle className="h-4 w-4 flex-shrink-0" />
					<span className="hidden lg:inline">New Assessment</span>
				</Button>
			</div>

			{/* Navigation Groups */}
			<div className="flex-1 space-y-4 overflow-y-auto pr-1">
				{navSections.map((section) => (
					<div key={section.title} className="space-y-1">
						<div className="hidden lg:block px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
							{section.title}
						</div>
						<div className="space-y-0.5">
							{section.items.map((item) => {
								const isSelected =
									activeView === item.view &&
									(item.view !== "findings" || !item.subTab || activeFindingsSubTab === item.subTab);

								return (
									<button
										key={`${item.view}-${item.subTab || "main"}`}
										onClick={() => onNavigate(item.view, item.subTab)}
										className={`
											w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-colors
											${
												isSelected
													? "bg-primary/15 text-primary font-semibold"
													: "text-muted-foreground hover:text-foreground hover:bg-muted/50"
											}
										`}
										title={item.label}
									>
										<span className="flex-shrink-0">{item.icon}</span>
										<span className="hidden lg:block flex-1 text-left truncate">
											{item.label}
										</span>
										{item.badge && (
											<span className="hidden lg:flex items-center">{item.badge}</span>
										)}
									</button>
								);
							})}
						</div>
					</div>
				))}
			</div>
		</aside>
	);
}
