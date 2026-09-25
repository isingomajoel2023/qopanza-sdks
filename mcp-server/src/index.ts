#!/usr/bin/env node
/**
 * MCP server for the Qopanza API.
 *
 * The product thesis in one file: the person who needs this most is not
 * going to read a security report. They are going to ask their coding
 * agent "is my app safe to launch", and the agent needs tools that
 * return something it can act on rather than prose it has to interpret.
 *
 * So every tool here returns two things — a human-readable block the
 * agent can relay, and a structured block it can work from. The
 * descriptions are written for a model deciding whether to call a tool,
 * which is a different audience from a developer reading docs, and they
 * matter more than they look: a tool the model never picks is a tool
 * that does not exist.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const BASE_URL = (
  process.env.QOPANZA_BASE_URL ?? "https://api.qopanza.com/v1"
).replace(/\/$/, "");
const API_KEY = process.env.QOPANZA_API_KEY ?? "";

interface Finding {
  kind: string;
  severity: string;
  confidence: string;
  title: string;
  location: string;
  line_number: number;
  evidence: string;
  explanation: string;
  remediation: string;
  fixable: boolean;
  /**
   * The database table a finding is about, when it is about one. The
   * agent passes findings back to `get_fixes` verbatim, and this is what
   * lets the generated row-level-security policy name the right table —
   * without it the server has only `location`, which is a file path.
   */
  table?: string | null;
}

interface ScanResponse {
  target: string;
  reachable: boolean;
  error?: string | null;
  files_scanned: string[];
  findings: Finding[];
  critical_count: number;
  high_count: number;
  score: number;
  summary: string;
  fix_available: boolean;
  fix_hint: string;
}

class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function call<T>(path: string, body: unknown): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (API_KEY) headers["X-API-Key"] = API_KEY;

  const response = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const parsed = (await response.json()) as { detail?: unknown };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      // Non-JSON error body; statusText is the best available.
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

/**
 * Render findings for the model to read aloud.
 *
 * Deliberately leads with the count and the worst item. A model
 * summarising a long list tends to describe the first thing it read, so
 * the first thing it reads should be the thing that matters.
 */
function renderScan(scan: ScanResponse): string {
  if (!scan.reachable) {
    return `Could not reach ${scan.target}.\n${scan.error ?? ""}`.trim();
  }

  const lines: string[] = [
    `Scanned ${scan.target} — security score ${scan.score}/100`,
    scan.summary,
    "",
    `Files checked: ${scan.files_scanned.length}`,
    "",
  ];

  if (scan.findings.length === 0) {
    lines.push("No problems found.");
    return lines.join("\n");
  }

  const sorted = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  for (const finding of sorted) {
    const where =
      finding.line_number > 0
        ? `${finding.location}:${finding.line_number}`
        : finding.location;
    const hedge = finding.confidence === "likely" ? " (needs confirming)" : "";
    lines.push(`[${finding.severity.toUpperCase()}]${hedge} ${finding.title}`);
    lines.push(`  where: ${where}`);
    lines.push(`  what:  ${finding.explanation}`);
    lines.push(`  fix:   ${finding.remediation}`);
    lines.push("");
  }

  lines.push(scan.fix_hint);
  return lines.join("\n");
}

const TOOLS = [
  {
    name: "scan_app_url",
    description:
      "Scan a deployed website for exposed API keys, database credentials and " +
      "missing security headers, given only its URL. Reads the JavaScript the " +
      "site actually serves, so anything found is ALREADY PUBLIC to every " +
      "visitor. Use this when the user asks whether their app is safe, secure, " +
      "or ready to launch, or mentions deploying. Works on Lovable, Bolt, v0, " +
      "Replit, Vercel and Netlify apps. Free — no API key required.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description:
            "The site's address. A bare domain like myapp.lovable.app is fine.",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "scan_app_code",
    description:
      "Scan one file's contents for hardcoded secrets (OpenAI, Stripe, AWS, " +
      "Supabase service keys) and database queries that let any visitor read " +
      "other people's rows. Use this while editing a file, or on files you just " +
      "wrote, before the user deploys. Free.",
    inputSchema: {
      type: "object",
      properties: {
        filename: {
          type: "string",
          description: "Path of the file, used to judge whether it ships to the browser.",
        },
        content: { type: "string", description: "The file's contents." },
      },
      required: ["filename", "content"],
    },
  },
  {
    name: "get_fixes",
    description:
      "Get the exact changes that fix findings from a scan: code edits with " +
      "before/after, config files to create, SQL policies, and the console steps " +
      "a human must do. Pass the findings array from scan_app_url or " +
      "scan_app_code. Requires a Pro plan; returns a clear message explaining " +
      "how to upgrade if the account is on Free.\n\n" +
      "IMPORTANT: steps have an `automatable` flag. Steps where it is false — " +
      "rotating a leaked key in the provider's dashboard, enabling RLS in " +
      "Supabase — CANNOT be done for the user. Never tell the user the problem " +
      "is fixed while any of those remain: a key removed from the code but not " +
      "rotated is still live and still public. Apply the automatable edits, then " +
      "list the manual steps and say plainly that they are outstanding.",
    inputSchema: {
      type: "object",
      properties: {
        findings: {
          type: "array",
          description: "The findings array returned by a scan tool, verbatim.",
          items: { type: "object" },
        },
        host: {
          type: "string",
          // Optional on purpose, and deliberately *not* a two-value enum.
          // An agent handed a choice between Vercel and Netlify will pick
          // one — that is what agents do — and the API would then return
          // a `vercel.json` for a Render site. Omitting this returns the
          // header values plus instructions that work anywhere, which is
          // the correct answer when nobody actually knows.
          enum: [
            "vercel",
            "netlify",
            "cloudflare_pages",
            "firebase",
            "render",
            "fly",
            "github_pages",
            "cloudfront",
            "s3",
            "digitalocean",
            "nginx",
            "other",
          ],
          description:
            "Where the app is deployed. OMIT THIS unless you actually know — " +
            "scan_app_url returns `detected_host`, read off the site's own " +
            "response headers; pass that value through if it is present. Do " +
            "not guess: a config file for the wrong platform is inert, and " +
            "the user will redeploy believing they are fixed. Omitted means " +
            "'unknown', which returns portable instructions instead.",
        },
      },
      required: ["findings"],
    },
  },
  {
    name: "scan_crypto",
    description:
      "Scan code for quantum-vulnerable cryptography (RSA, ECDSA, ECDH, MD5, " +
      "SHA-1) and report a quantum risk score. Use this when the user asks about " +
      "quantum safety, post-quantum readiness, or crypto compliance. Note: most " +
      "apps built on Lovable/Bolt/v0 have no cryptography of their own, so an " +
      "empty result here is normal and not a problem — prefer scan_app_url for " +
      "'is my app secure'. Free.",
    inputSchema: {
      type: "object",
      properties: {
        filename: { type: "string" },
        content: { type: "string" },
      },
      required: ["filename", "content"],
    },
  },
];

const server = new Server(
  { name: "quantum-safe", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "scan_app_url": {
        const scan = await call<ScanResponse>("/app-scan/url", { url: args.url });
        return {
          content: [{ type: "text", text: renderScan(scan) }],
          structuredContent: scan as unknown as Record<string, unknown>,
        };
      }

      case "scan_app_code": {
        const scan = await call<ScanResponse>("/app-scan/code", {
          filename: args.filename,
          content: args.content,
        });
        return {
          content: [{ type: "text", text: renderScan(scan) }],
          structuredContent: scan as unknown as Record<string, unknown>,
        };
      }

      case "get_fixes": {
        const plan = await call<{
          remediations: Array<{
            title: string;
            summary: string;
            risk_if_ignored: string;
            steps: Array<{
              order: number;
              title: string;
              detail: string;
              automatable: boolean;
              file?: string | null;
              line?: number | null;
              before?: string | null;
              after?: string | null;
              create_file?: string | null;
              create_content?: string | null;
              console_url?: string | null;
            }>;
          }>;
          total: number;
          manual_steps_required: number;
          // `?? null`, never `?? "vercel"`. The fallback used to be a
          // literal "vercel", so an agent that sensibly declined to guess
          // had Vercel asserted on its behalf anyway.
        }>("/app-scan/fix", { findings: args.findings, host: args.host ?? null });

        const lines: string[] = [
          `${plan.total} fix${plan.total === 1 ? "" : "es"} generated.`,
          "",
        ];
        for (const remediation of plan.remediations) {
          lines.push(`## ${remediation.title}`);
          lines.push(remediation.summary);
          lines.push(`Risk if ignored: ${remediation.risk_if_ignored}`);
          for (const step of remediation.steps) {
            const tag = step.automatable ? "[you can do this]" : "[USER MUST DO THIS]";
            lines.push(`  ${step.order}. ${tag} ${step.title}`);
            lines.push(`     ${step.detail}`);
            if (step.file) lines.push(`     file: ${step.file}:${step.line ?? ""}`);
            if (step.create_file) lines.push(`     create: ${step.create_file}`);
            if (step.console_url) lines.push(`     go to: ${step.console_url}`);
          }
          lines.push("");
        }
        // Repeated at the end because a model summarising a long response
        // weights the last thing it read, and this is the sentence that
        // stops it reporting a half-done fix as finished.
        lines.push(
          `${plan.manual_steps_required} step(s) require the user and cannot be ` +
            `automated. The problem is NOT fixed until those are done — in ` +
            `particular, a leaked key that has not been rotated is still live.`,
        );

        return {
          content: [{ type: "text", text: lines.join("\n") }],
          structuredContent: plan as unknown as Record<string, unknown>,
        };
      }

      case "scan_crypto": {
        const scan = await call<Record<string, unknown>>("/scan/code", {
          filename: args.filename,
          content: args.content,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(scan, null, 2) }],
          structuredContent: scan,
        };
      }

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (error) {
    // 402 is the interesting one: it is not a failure, it is a price. The
    // model should relay it as an option rather than as an error the user
    // needs to debug, so it is phrased that way here.
    if (error instanceof ApiError && error.status === 402) {
      return {
        content: [
          {
            type: "text",
            text:
              `This needs a paid plan.\n\n${error.message}\n\n` +
              `The scan results you already have are complete — nothing was ` +
              `hidden. You can fix the problems by hand from the descriptions, ` +
              `or upgrade to have the exact changes generated.`,
          },
        ],
      };
    }
    if (error instanceof ApiError && error.status === 401) {
      return {
        content: [
          {
            type: "text",
            text:
              "No valid API key. Set QOPANZA_API_KEY in this MCP server's " +
              "environment. A free key takes about a minute to create.",
          },
        ],
        isError: true,
      };
    }
    return {
      content: [
        {
          type: "text",
          text: `Scan failed: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

async function main(): Promise<void> {
  // stdio, so the agent launches this as a subprocess. Nothing may be
  // written to stdout except protocol frames — a stray console.log
  // corrupts the stream and the server appears to hang.
  await server.connect(new StdioServerTransport());
  console.error(`quantum-safe MCP server ready (api: ${BASE_URL})`);
}

main().catch((error) => {
  console.error("Fatal:", error);
  process.exit(1);
});
