# AETERNA GPT — WebMCP MVP

A fresh WebMCP-native guarded-agent build for the 2026 WebMCP Challenge.

## What it does

AETERNA GPT exposes structured browser tools that let an agent inspect untrusted project content, scan for deterministic security findings, propose an in-memory patch, validate that patch, and stop at an explicit approval boundary before any consequential action.

Core flow:

`DISCOVER → INSPECT → ANALYZE → PROPOSE → VALIDATE → APPROVAL BOUNDARY`

The product principle is simple: **trusted agents should do trusted work**. Read-only analysis and validation run autonomously. Consequential actions are not exposed as free-running behavior.

## WebMCP tools

The page registers these tools with `document.modelContext.registerTool(...)`:

- `get_audit_engagement` — loads the pinned Europeum scope, reward, deadline, and reporting constraints.
- `preflight_audit` — verifies repository, commit, file scope, and submission eligibility before analysis.
- `inspect_project` — read-only inspection of project text treated as untrusted content.
- `scan_security` — deterministic evidence-backed scan that fails closed on out-of-scope engagement files.
- `propose_patch` — generates a non-persistent patch proposal in memory.
- `validate_patch` — rescans the proposed patch without external mutation.
- `request_human_approval` — records an approval request for a consequential action but does not execute it.

The tool definitions use strict JSON-style input schemas and WebMCP annotations including `readOnlyHint` and `untrustedContentHint` where appropriate. Registration attempts origin scoping and cancellation support and falls back to basic registration if a browser implementation does not yet accept those options.

## Trust envelope

### Autonomous

Inspect, read, analyze, classify, propose, validate, and produce evidence.

### Scoped autonomous

Pre-authorized sandbox/test actions may be added later, but this V1 does not persistently write project files.

### Approval required

Production deployment, signing, payments, destructive writes, protected-branch changes, secret rotation, and external commitments are outside the autonomous MVP boundary.

If input is missing, ambiguous, or rejected by policy, the demo fails closed and preserves state.

## Europeum audit profile

The versioned profile at `audit/europeum-engagement.json` configures AETERNA for the Europeum Core Services API DualDefense Audit:

- source repository `https://gitlab.com/europeum/public/core-services`;
- pinned commit `60a26443bde7f9487239aaa73d52f555fd871c30`;
- only eligible `api/**` source paths, with tests, build output, configuration, documentation, and all non-API packages excluded;
- up to $5,000 USD equivalent in USDC, with a September 17, 2026 deadline whose timezone is not stated;
- a 50-point HackenProof reputation minimum, KYC, and acceptance of the $2 submission fee;
- only critical impact causing fund loss or permanent fund locking;
- a runnable proof of concept, concise reproduction steps, and a proposed fix.

The profile does not grant permission to test live systems. AETERNA handles source supplied locally and labels heuristic matches as unproven candidates. It does not submit reports, contact the target, disclose findings, or claim reward eligibility.

## Judge demo

1. Open the live page in ChatGPT's in-app browser or Chrome with WebMCP enabled.
2. The included demo project contains three intentionally safe-to-demonstrate findings: a hard-coded demo credential-like string, an unsafe `innerHTML` assignment, and a credential-like value in a URL.
3. Ask the agent to inspect and audit the demo project, or press **Run guarded audit** to observe the same trust model through the UI.
4. AETERNA GPT produces structured findings, proposes a patch, validates the patch, and then demonstrates that a hypothetical production deployment stops at an approval boundary.
5. Even if approval is granted in the demo UI, no production deploy capability exists in this MVP.

## Challenge-period provenance

This repository is the fresh competition implementation. An earlier Aeterna concept existed as a Replit/Chrome-extension-style code-auditing idea, but that earlier implementation is not used as the competition codebase.

The challenge-period additions in this repository are:

- the WebMCP-native tool registry;
- structured tool input schemas and annotations;
- the explicit trust-envelope policy;
- safe handling of untrusted project content;
- deterministic finding and patch-proposal flow;
- non-mutating validation;
- the human approval boundary;
- the judge-visible browser experience and evidence stream.

## Current limitations

This is intentionally a small, deterministic MVP. It does not execute shell commands, fetch or inspect arbitrary private repositories, deploy production code, sign transactions, spend funds, extract real secrets, test live systems, submit bounty reports, or persistently modify external systems. The security scan demonstrates the agent workflow using a bounded set of heuristics rather than claiming full static-analysis coverage.

## Run locally

This is a static application. Serve the repository root with any static HTTP server and open it in a WebMCP-capable browser. No API key or backend is required for the V1 demo.

Run the policy checks with:

`node --test tests/audit-policy.test.mjs`

## License

MIT.
