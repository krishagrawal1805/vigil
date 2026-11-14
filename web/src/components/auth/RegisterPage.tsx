import React, { useState } from "react";
import { useRegisterMutation } from "@/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ShieldCheck, AlertTriangle, UserPlus, CheckCircle2, ArrowLeft, Eye, EyeOff, Sparkles, LogIn } from "lucide-react";

interface RegisterPageProps {
	onSwitchToLogin: () => void;
	onBackToWebsite?: () => void;
}

export function RegisterPage({ onSwitchToLogin, onBackToWebsite }: RegisterPageProps) {
	const [fullName, setFullName] = useState("");
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [showPassword, setShowPassword] = useState(false);
	const [orgId, setOrgId] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [successMsg, setSuccessMsg] = useState<string | null>(null);
	const [isUsernameCustomized, setIsUsernameCustomized] = useState(false);

	const [register, { isLoading }] = useRegisterMutation();

	// When user types their full name, automatically suggest a clean username if they haven't manually typed a custom username
	const handleFullNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		const val = e.target.value;
		setFullName(val);
		if (!isUsernameCustomized) {
			const sanitized = val.toLowerCase().replace(/[^a-z0-9_-]/g, "");
			setUsername(sanitized);
		}
	};

	const handleUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_.-]/g, ""));
		setIsUsernameCustomized(true);
	};

	const handleRegister = async (e: React.FormEvent) => {
		e.preventDefault();
		setError(null);
		setSuccessMsg(null);

		const finalUsername = username.trim() || fullName.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
		if (!finalUsername) {
			setError("Please enter a username or full name.");
			return;
		}

		try {
			const res = await register({
				name: fullName.trim() || undefined,
				username: finalUsername,
				password,
				org_id: orgId.trim() || undefined,
				role: "pentester",
			}).unwrap();

			localStorage.setItem("last_username", res.user.username);
			setSuccessMsg(`Registered account "${res.user.username}" successfully! Redirecting to sign in...`);
			setTimeout(() => {
				onSwitchToLogin();
			}, 1500);
		} catch (err: any) {
			setError(err?.data?.error || err?.message || "Registration failed.");
		}
	};

	// Determine if error is about username being already taken
	const isUsernameTaken = Boolean(error && error.toLowerCase().includes("already taken"));

	return (
		<div className="flex flex-col min-h-[85vh] items-center justify-center p-4">
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
				<CardHeader className="space-y-2 text-center pb-4">
					<div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-600">
						<ShieldCheck className="h-6 w-6" />
					</div>
					<CardTitle className="text-xl font-bold tracking-tight">Create Operator Account</CardTitle>
					<CardDescription className="text-xs">
						Register your VIGIL testing identity. Full names can be shared, while usernames provide unique sign-in credentials.
					</CardDescription>
				</CardHeader>

				<form onSubmit={handleRegister}>
					<CardContent className="space-y-4">
						{error && (
							<Alert variant="destructive" className="py-2.5">
								<AlertTriangle className="h-4 w-4" />
								<div className="flex-1">
									<AlertTitle className="text-xs font-semibold">Registration Notice</AlertTitle>
									<AlertDescription className="text-xs mt-0.5">{error}</AlertDescription>
									{isUsernameTaken && (
										<div className="mt-2.5 pt-2 border-t border-destructive/20 flex flex-wrap gap-1.5 items-center">
											<span className="text-[11px] font-medium text-destructive-foreground/80">Suggestions:</span>
											<button
												type="button"
												onClick={() => {
													setUsername(`${username}_${Math.floor(Math.random() * 90 + 10)}`);
													setError(null);
												}}
												className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-background/80 hover:bg-background text-[11px] font-mono border border-border text-foreground transition-colors"
											>
												<Sparkles className="h-3 w-3 text-emerald-500" />
												Use {username}_1
											</button>
											<button
												type="button"
												onClick={() => {
													localStorage.setItem("last_username", username);
													onSwitchToLogin();
												}}
												className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-primary text-primary-foreground hover:bg-primary/90 text-[11px] font-medium transition-colors"
											>
												<LogIn className="h-3 w-3" />
												Sign In as {username}
											</button>
										</div>
									)}
								</div>
							</Alert>
						)}

						{successMsg && (
							<Alert className="py-2.5 border-emerald-500/30 bg-emerald-500/10 text-emerald-700">
								<CheckCircle2 className="h-4 w-4 text-emerald-600" />
								<AlertTitle className="text-xs font-semibold">Registration Successful</AlertTitle>
								<AlertDescription className="text-xs">{successMsg}</AlertDescription>
							</Alert>
						)}

						{/* 1. Full Name */}
						<div className="space-y-1.5">
							<div className="flex items-center justify-between">
								<Label htmlFor="reg-fullname" className="text-xs font-medium">Full Name (Display Name)</Label>
								<span className="text-[10px] text-muted-foreground">Can be shared with others</span>
							</div>
							<Input
								id="reg-fullname"
								type="text"
								placeholder="e.g. Krishna Agrawal"
								value={fullName}
								onChange={handleFullNameChange}
								autoFocus
								className="h-9"
							/>
						</div>

						{/* 2. Username */}
						<div className="space-y-1.5">
							<div className="flex items-center justify-between">
								<Label htmlFor="reg-username" className="text-xs font-medium">Username (Sign-in ID)</Label>
								<span className="text-[10px] text-emerald-600 font-medium">Unique Identifier</span>
							</div>
							<Input
								id="reg-username"
								type="text"
								placeholder="e.g. krishna or krishna_dev"
								value={username}
								onChange={handleUsernameChange}
								required
								className="h-9 font-mono text-sm"
							/>
							<p className="text-[10px] text-muted-foreground">
								Used exclusively to log in to your account.
							</p>
						</div>

						{/* 3. Password */}
						<div className="space-y-1.5">
							<Label htmlFor="reg-password" className="text-xs font-medium">Password</Label>
							<div className="relative">
								<Input
									id="reg-password"
									type={showPassword ? "text" : "password"}
									placeholder="At least 8 characters"
									value={password}
									onChange={(e) => setPassword(e.target.value)}
									required
									minLength={8}
									className="h-9 pr-9"
								/>
								<button
									type="button"
									onClick={() => setShowPassword(!showPassword)}
									className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
								>
									{showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
								</button>
							</div>
							<p className="text-[10px] text-muted-foreground">
								Cryptographically hashed using PBKDF2-HMAC-SHA256 (600,000 iterations).
							</p>
						</div>

						{/* 4. Organization ID */}
						<div className="space-y-1.5">
							<Label htmlFor="reg-org" className="text-xs font-medium">Organization ID (Optional)</Label>
							<Input
								id="reg-org"
								type="text"
								placeholder="e.g. org-acme-sec (leave blank for auto-generated)"
								value={orgId}
								onChange={(e) => setOrgId(e.target.value)}
								className="h-9"
							/>
						</div>
					</CardContent>

					<CardFooter className="flex flex-col gap-3 pt-2">
						<Button type="submit" className="w-full gap-2 h-10" isLoading={isLoading} disabled={Boolean(successMsg)}>
							<UserPlus className="h-4 w-4" />
							Register Operator Account
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
