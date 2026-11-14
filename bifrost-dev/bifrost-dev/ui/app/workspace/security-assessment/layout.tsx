import { createFileRoute } from "@tanstack/react-router";
import SecurityAssessmentPage from "./page";

function RouteComponent() {
	return <SecurityAssessmentPage />;
}

export const Route = createFileRoute("/workspace/security-assessment")({
	component: RouteComponent,
});

