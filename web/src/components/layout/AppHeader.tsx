import React from "react";
import {
  useGetProfileQuery,
  useGetWorkspacesQuery,
  useLogoutMutation,
  useGetAssessmentStatusQuery,
} from "@/store";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Shield, LogOut, Activity, Bug, ClipboardList, Target, RefreshCw } from "lucide-react";

interface AppHeaderProps {
  onRefreshAll: () => void;
  onLogout: () => void;
  activeView: string;
  onNavigate: (view: string, subTab?: string) => void;
  findingsCount?: number;
}

export function AppHeader({
  onRefreshAll,
  onLogout,
  activeView,
  onNavigate,
  findingsCount = 0,
}: AppHeaderProps) {
  const { data: profile } = useGetProfileQuery();
  const { data: liveStatus } = useGetAssessmentStatusQuery(undefined, {
    pollingInterval: 3000,
    skip: !profile,
  });
  const [logout, { isLoading: isLoggingOut }] = useLogoutMutation();

  const handleLogoutClick = async () => {
    try {
      await logout().unwrap();
    } catch {
      // Logout anyway
    }
    onLogout();
  };

  const isAssessmentRunning =
    liveStatus?.status === "running" || liveStatus?.status === "starting";

  return (
    <header className="sticky top-0 z-40 border-b border-slate-200 bg-white/95 backdrop-blur-sm h-14">
      <div className="h-full max-w-7xl mx-auto px-4 sm:px-6 flex items-center justify-between gap-4">
        {/* Brand / Logo */}
        <div
          onClick={() => onNavigate("welcome")}
          className="flex items-center gap-2.5 cursor-pointer hover:opacity-90 transition-opacity"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white shadow-xs">
            <Shield className="h-4 w-4" />
          </div>
          <div className="flex flex-col">
            <span className="font-extrabold text-sm tracking-wider text-slate-900">
              VIGIL
            </span>
            <span className="text-[9px] text-slate-500 leading-none hidden sm:block font-medium">
              Autonomous Pentesting
            </span>
          </div>
        </div>

        {/* Center: Modern Navigation Tabs (Eliminates the clunky sideline) */}
        <nav className="flex items-center gap-1 sm:gap-2">
          {/* 1. Target Selection */}
          <button
            onClick={() => onNavigate("welcome")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === "welcome" || activeView === "external-workflow"
                ? "bg-blue-50 text-blue-700 border border-blue-200 shadow-xs"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
            }`}
          >
            <Target className="h-3.5 w-3.5" />
            <span>Target Selection</span>
          </button>

          {/* 2. Live Assessment */}
          <button
            onClick={() => onNavigate("live-assessment")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === "live-assessment"
                ? "bg-blue-50 text-blue-700 border border-blue-200 shadow-xs"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            <span>Live Scan</span>
            {isAssessmentRunning && (
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            )}
          </button>

          {/* 3. Findings & Report */}
          <button
            onClick={() => onNavigate("findings", "overview")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === "findings"
                ? "bg-blue-50 text-blue-700 border border-blue-200 shadow-xs"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
            }`}
          >
            <Bug className="h-3.5 w-3.5" />
            <span>Results & Report</span>
            {findingsCount > 0 ? (
              <span className="text-[10px] font-bold bg-rose-100 text-rose-700 border border-rose-200 px-1.5 py-0.2 rounded-full">
                {findingsCount}
              </span>
            ) : null}
          </button>

          {/* 4. Audit Trail */}
          <button
            onClick={() => onNavigate("audit")}
            className={`hidden md:flex px-3 py-1.5 rounded-lg text-xs font-semibold items-center gap-1.5 transition-all ${
              activeView === "audit"
                ? "bg-blue-50 text-blue-700 border border-blue-200 shadow-xs"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
            }`}
          >
            <ClipboardList className="h-3.5 w-3.5" />
            <span>Audit</span>
          </button>
        </nav>

        {/* Right: User + Refresh + Logout */}
        <div className="flex items-center gap-2">
          {/* Refresh Action */}
          <button
            onClick={onRefreshAll}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors"
            title="Refresh All Data"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>

          {/* User Badge */}
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-md border border-slate-200 bg-slate-50 text-xs">
            <div className="h-2 w-2 rounded-full bg-emerald-500" />
            <span className="font-semibold text-slate-800">
              {profile?.username || "pentester"}
            </span>
            <span className="text-[9px] font-bold text-slate-500 uppercase">
              {profile?.role || "pentester"}
            </span>
          </div>

          {/* Logout */}
          <Button
            variant="ghost"
            size="sm"
            onClick={handleLogoutClick}
            isLoading={isLoggingOut}
            className="text-slate-500 hover:text-rose-600 h-8 w-8 p-0"
            title="Sign out"
          >
            <LogOut className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </header>
  );
}
