import * as React from "react";
import { cn } from "@/lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
	inputClassName?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
	({ className, type, ...props }, ref) => {
		return (
			<input
				type={type}
				ref={ref}
				data-slot="input"
				className={cn(
					"border-input placeholder:text-muted-foreground focus-visible:border-primary focus-visible:ring-primary/20 flex h-9 w-full rounded-sm border bg-background px-3 py-1 text-sm shadow-none transition-colors outline-none focus-visible:ring-2 disabled:cursor-not-allowed disabled:opacity-50",
					className,
				)}
				{...props}
			/>
		);
	},
);

Input.displayName = "Input";
