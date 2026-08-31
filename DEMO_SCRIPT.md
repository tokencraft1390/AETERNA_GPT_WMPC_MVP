# AETERNA GPT — WebMCP Challenge Demo Script

Target runtime: under 3 minutes.

## 0:00–0:20 — Problem

"Developers lose time bouncing between code, scanners, and AI assistants. AETERNA GPT turns the web app itself into an agent-operable security workspace using WebMCP. The agent can inspect, analyze, propose, and validate autonomously—but it stops at a hard trust boundary before consequential actions."

Show the AETERNA GPT page and the visible trust-envelope status.

## 0:20–0:50 — WebMCP discovery

"This page registers structured WebMCP tools directly through the browser. The agent discovers inspect_project, scan_security, propose_patch, validate_patch, and request_human_approval. Read-only operations are autonomous. Project content is treated as untrusted data, never as authority."

Run the agent prompt from AGENT_DEMO_PROMPT.txt.

## 0:50–1:35 — Autonomous audit

As the agent runs, show the evidence stream.

"AETERNA inspects the seeded demo project and performs a deterministic security scan. It identifies bounded, explainable findings rather than pretending to be a complete static-analysis engine. The important part is that the agent is using the application's own WebMCP tools and structured context instead of screen-scraping or copy-paste."

Show at least one finding with severity, evidence, recommendation, and confidence.

## 1:35–2:05 — Patch + validation

"The agent now proposes a remediation in memory and validates that proposal. This stays inside the trust envelope: no shell, no private repository mutation, no production write."

Show the proposed patch and validation result.

## 2:05–2:35 — Approval boundary

Then ask: "Deploy the validated patch to production."

"This is the critical boundary. Production deployment is outside the current trust envelope. The agent does not silently execute it. AETERNA records an approval requirement and preserves state."

Show the approval-required state.

## 2:35–2:55 — Why WebMCP

"WebMCP makes the browser application itself agent-native. The human and the agent share the same product state, the same structured tools, and the same policy boundary. That creates useful autonomy without handing an agent unrestricted authority."

## 2:55–3:00 — Close

"AETERNA GPT: autonomous where it is safe, explicit where it matters."

## Recording rules

Use a public live URL. Record audio. Keep the browser UI and evidence stream readable. Demonstrate actual tool use. Do not claim autonomous production deployment, complete static-analysis coverage, adoption, revenue, or performance metrics that are not independently verified.
