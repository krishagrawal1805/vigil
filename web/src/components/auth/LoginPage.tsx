import React, { useState } from "react";
import { useLoginMutation } from "@/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Shield,
  AlertTriangle,
  Lock,
  Eye,
  EyeOff,
  Zap,
  Target,
  CheckCircle2,
  Activity,
  ArrowLeft,
} from "lucide-react";

interface LoginPageProps {
  onSuccess?: () => void;
  onSwitchToRegister: () => void;
  onBackToWebsite?: () => void;
}

export function LoginPage({ onSuccess, onSwitchToRegister, onBackToWebsite }: LoginPageProps) {
  const [username, setUsername] = useState(() => localStorage.getItem("last_username") || "");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [login, { isLoading }] = useLoginMutation();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await login({ username, password }).unwrap();
      localStorage.setItem("last_username", username);
      onSuccess?.();
    } catch (err: any) {
      setError(
        err?.data?.error ||
          err?.message ||
          "Authentication failed. Check credentials or register a new pentester account."
      );
    }
  };

  const features = [
    {
      icon: <Zap className="h-4 w-4 text-primary" />,
      title: "Autonomous AI Agents",
      desc: "Multi-agent orchestration for comprehensive security testing",
    },
    {
      icon: <Target className="h-4 w-4 text-primary" />,
      title: "Deterministic Scope Enforcement",
      desc: "Cryptographic authorization grants protect every target",
    },
    {
      icon: <CheckCircle2 className="h-4 w-4 text-primary" />,
      title: "Evidence-Based Findings",
      desc: "Independent finding verification through automated exploit validation",
    },
    {
      icon: <Activity className="h-4 w-4 text-primary" />,
      title: "Real-Time Intelligence",
      desc: "Live assessment polling updates with full audit trail",
    },
  ];

  return (
    <div className="min-h-screen bg-background flex">
      {/* Grid pattern overlay */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(56,189,248,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.5) 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
        }}
      />

      {/* Left Panel */}
      <div className="hidden lg:flex flex-col justify-center w-1/2 px-16 relative z-10">
        {/* Logo */}
        <div className="mb-12">
          <div className="flex items-center gap-3 mb-6">
            <div className="h-12 w-12 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-black tracking-widest text-foreground">
                VIGIL
              </h1>
              <p className="text-xs text-primary font-medium tracking-wider uppercase">
                Autonomous Security Intelligence Platform
              </p>
            </div>
          </div>

          <p className="text-muted-foreground text-sm leading-relaxed max-w-sm">
            Enterprise-grade autonomous penetration testing with multi-agent AI
            orchestration. Authorized, scoped, and audit-ready.
          </p>
        </div>

        {/* Features */}
        <div className="space-y-5">
          {features.map((f, i) => (
            <div key={i} className="flex items-start gap-3">
              <div className="mt-0.5 h-8 w-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                {f.icon}
              </div>
              <div>
                <p className="text-sm font-semibold text-foreground">
                  {f.title}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5">{f.desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Bottom tag: Real security controls */}
        <div className="mt-16 flex items-center gap-2 text-xs text-muted-foreground/60">
          <div className="h-px flex-1 bg-border/40" />
          <span>Deterministic ScopeEnforcer Gating • Multi-Agent Cryptographic Verification • Real-Time Audit Trail</span>
          <div className="h-px flex-1 bg-border/40" />
        </div>
      </div>

      {/* Right Panel - Login Form */}
      <div className="flex flex-col justify-center w-full lg:w-1/2 px-6 sm:px-12 lg:px-16 relative z-10">
        <div className="w-full max-w-sm mx-auto">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-2 mb-8">
            <div className="h-9 w-9 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <span className="text-2xl font-black tracking-widest text-foreground">
              VIGIL
            </span>
          </div>

          {onBackToWebsite && (
            <button
              type="button"
              onClick={onBackToWebsite}
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground mb-4 transition-colors font-medium group"
            >
              <ArrowLeft className="h-3.5 w-3.5 transition-transform group-hover:-translate-x-0.5" />
              Back to Product Website
            </button>
          )}

          <div className="mb-8">
            <h2 className="text-xl font-bold text-foreground">
              Sign in to your workspace
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              Authorized operators only
            </p>
          </div>

          {error && (
            <Alert variant="destructive" className="mb-4 py-2.5">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription className="text-xs">{error}</AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="username" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Username or Sign-in ID
              </Label>
              <Input
                id="username"
                type="text"
                placeholder="e.g. krishna or admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
                className="bg-muted/30 border-border/60 focus:border-primary/50 h-10"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Password
              </Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="bg-muted/30 border-border/60 focus:border-primary/50 h-10 pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            <Button
              type="submit"
              className="w-full gap-2 h-10 mt-2"
              isLoading={isLoading}
            >
              <Lock className="h-4 w-4" />
              Authenticate
            </Button>
          </form>

          <p className="text-center text-xs text-muted-foreground mt-6">
            Need an account?{" "}
            <button
              type="button"
              onClick={onSwitchToRegister}
              className="text-primary hover:underline font-medium"
            >
              Request Operator Access
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
