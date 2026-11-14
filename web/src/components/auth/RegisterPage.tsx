import React, { useState } from "react";
import { useRegisterMutation } from "@/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ShieldCheck, AlertTriangle, UserPlus, CheckCircle2, ArrowLeft } from "lucide-react";

interface RegisterPageProps {
	onSwitchToLogin: () => void;
	onBackToWebsite?: () => void;
}

export function RegisterPage({ onSwitchToLogin, onBackToWebsite }: RegisterPageProps) {
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [orgId, setOrgId] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [successMsg, setSuccessMsg] = useState<string | null>(null);

	const [register, { isLoading }] = useRegisterMutation();

	const handleRegister = async (e: React.FormEvent) => {
		e.preventDefault();
		setError(null);
		setSuccessMsg(null);
		try {
			const res = await register({
				username,
				password,
				org_id: orgId.trim() || undefined,
				role: "pentester",
			}).unwrap();

			localStorage.setItem("last_username", res.user.username);
			setSuccessMsg(`Registered user "${res.user.username}" (Org: ${res.user.org_id}, Role: ${res.user.role}). Redirecting to sign in...`);
			setTimeout(() => {
				onSwitchToLogin();
			}, 1800);
		} catch (err: any) {
			setError(err?.data?.error || err?.message || "Registration failed.");
		}
	};

	return (
		<div className="flex flex-col min-h-[80vh] items-center justify-center p-4">
			{onBackToWebsite && (
				<div className="w-full max-w-md mb-3">
					<button
						type="button"
						onClick={onBackToWebsite}
						className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors font-medium group"
					>
						<ArrowLeft className="h-3.5 w-3.5 transition-transform group-hover:-translate-x-0.5" />
						Back to Product Website
					</button>
				</div>
			)}
			<Card className="w-full max-w-md border-border/80 shadow-lg">
				<CardHeader className="space-y-2 text-center">
					<div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-600">
						<ShieldCheck className="h-6 w-6" />
					</div>
					<CardTitle className="text-xl font-bold tracking-tight">Create Pentester Account</CardTitle>
					<CardDescription className="text-xs">
						Register as a penetration tester. Default unprivileged role (pentester) is assigned; privilege escalation is strictly prohibited.
					</CardDescription>
				</CardHeader>

				<form onSubmit={handleRegister}>
					<CardContent className="space-y-4">
						{error && (
							<Alert variant="destructive" className="py-2.5">
								<AlertTriangle className="h-4 w-4" />
								<AlertTitle className="text-xs font-semibold">Registration Rejected</AlertTitle>
								<AlertDescription className="text-xs">{error}</AlertDescription>
							</Alert>
						)}

						{successMsg && (
							<Alert className="py-2.5 border-emerald-500/30 bg-emerald-500/10 text-emerald-700">
								<CheckCircle2 className="h-4 w-4 text-emerald-600" />
								<AlertTitle className="text-xs font-semibold">Registration Successful</AlertTitle>
								<AlertDescription className="text-xs">{successMsg}</AlertDescription>
							</Alert>
						)}

						<div className="space-y-1.5">
							<Label htmlFor="reg-username">Username</Label>
							<Input
								id="reg-username"
								type="text"
								placeholder="e.g. dev-tester-1"
								value={username}
								onChange={(e) => setUsername(e.target.value)}
								required
								autoFocus
							/>
						</div>

						<div className="space-y-1.5">
							<Label htmlFor="reg-password">Password</Label>
							<Input
								id="reg-password"
								type="password"
								placeholder="At least 8 characters"
								value={password}
								onChange={(e) => setPassword(e.target.value)}
								required
								minLength={8}
							/>
							<p className="text-[10px] text-muted-foreground">
								Passwords are cryptographically salted and hashed with PBKDF2-HMAC-SHA256 (100,000 iterations).
							</p>
						</div>

						<div className="space-y-1.5">
							<Label htmlFor="reg-org">Organization ID (Optional)</Label>
							<Input
								id="reg-org"
								type="text"
								placeholder="e.g. org-acme-sec (leave blank for auto-generated)"
								value={orgId}
								onChange={(e) => setOrgId(e.target.value)}
							/>
							<p className="text-[10px] text-muted-foreground">
								System protected organizations ("org-cyber-defense") cannot be self-claimed.
							</p>
						</div>
					</CardContent>

					<CardFooter className="flex flex-col gap-3">
						<Button type="submit" className="w-full gap-2" isLoading={isLoading} disabled={Boolean(successMsg)}>
							<UserPlus className="h-4 w-4" />
							Register Account
						</Button>
						<p className="text-center text-xs text-muted-foreground">
							Already have an account?{" "}
							<button
								type="button"
								onClick={onSwitchToLogin}
								className="text-primary hover:underline font-medium"
							>
								Sign In
							</button>
						</p>
					</CardFooter>
				</form>
			</Card>
		</div>
	);
}

