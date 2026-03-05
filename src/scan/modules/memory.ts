declare function require(name: string): any;

const fs = require("fs");
const path = require("path");

import { Finding } from "../../report/schema";
import { LlmConfig, chatCompletion, parseFindingsFromLLM } from "../llm";
import { ModuleResult } from "../types";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_SCAN_FILES = 100;

const SECRET_PATTERNS: Array<{ re: RegExp; label: string }> = [
  // OpenAI / LLM provider keys
  { re: /sk-[A-Za-z0-9]{20,}/, label: "OpenAI-style API key (sk-...)" },
  { re: /sk-proj-[A-Za-z0-9_-]{20,}/, label: "OpenAI project API key (sk-proj-...)" },
  // GitHub tokens
  { re: /ghp_[A-Za-z0-9]{36,}/, label: "GitHub personal access token (ghp_...)" },
  { re: /gho_[A-Za-z0-9]{36,}/, label: "GitHub OAuth token (gho_...)" },
  { re: /ghs_[A-Za-z0-9]{36,}/, label: "GitHub App installation token (ghs_...)" },
  { re: /github_pat_[A-Za-z0-9_]{22,}/, label: "GitHub fine-grained PAT" },
  // GitLab tokens
  { re: /glpat-[A-Za-z0-9_\-]{20,}/, label: "GitLab personal access token (glpat-...)" },
  { re: /gldt-[A-Za-z0-9_\-]{20,}/, label: "GitLab deploy token (gldt-...)" },
  // Slack
  { re: /xoxb-[0-9A-Za-z\-]{24,}/, label: "Slack bot token (xoxb-...)" },
  { re: /xoxp-[0-9A-Za-z\-]{24,}/, label: "Slack user token (xoxp-...)" },
  { re: /xoxs-[0-9A-Za-z\-]{24,}/, label: "Slack session token (xoxs-...)" },
  { re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}/, label: "Slack webhook URL" },
  // AWS
  { re: /AKIA[0-9A-Z]{16}/, label: "AWS access key (AKIA...)" },
  { re: /ASIA[0-9A-Z]{16}/, label: "AWS temporary access key (ASIA...)" },
  // Google Cloud
  { re: /AIza[A-Za-z0-9_\-]{35}/, label: "Google Cloud API key (AIza...)" },
  // Azure
  { re: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i, label: "Azure/UUID-style secret (potential client-id or subscription key)" },
  // Stripe
  { re: /sk_live_[A-Za-z0-9]{24,}/, label: "Stripe secret key (sk_live_...)" },
  { re: /rk_live_[A-Za-z0-9]{24,}/, label: "Stripe restricted key (rk_live_...)" },
  // SendGrid
  { re: /SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}/, label: "SendGrid API key (SG.…)" },
  // Twilio
  { re: /SK[a-f0-9]{32}/, label: "Twilio API key (SK...)" },
  // PEM / SSH private keys
  { re: /-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, label: "PEM/SSH private key" },
  // Database connection strings
  { re: /(mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^\s"']{10,}/, label: "Database connection URL" },
  // JWT
  { re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\./, label: "JWT token" },
  // HTTP Basic Auth
  { re: /Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}/i, label: "HTTP Basic Auth header" },
  // Anthropic
  { re: /sk-ant-[A-Za-z0-9_\-]{20,}/, label: "Anthropic API key (sk-ant-...)" },
  // Hugging Face
  { re: /hf_[A-Za-z0-9]{20,}/, label: "Hugging Face token (hf_...)" },
  // Generic high-entropy catch-all
  {
    re: /(api[_-]?key|api[_-]?secret|token|password|secret|credential|auth_token|access_token|secret_key)\s*[:=]\s*["']?[A-Za-z0-9_\-/.]{16,}/i,
    label: "Generic secret assignment",
  },
];

const PII_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/, label: "Email address" },
  { re: /\b1[3-9]\d{9}\b/, label: "Chinese mobile phone number" },
  { re: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/, label: "US phone number pattern" },
  {
    re: /\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/,
    label: "Chinese national ID number",
  },
  { re: /\b\d{3}-\d{2}-\d{4}\b/, label: "US SSN pattern" },
  { re: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, label: "Credit card number" },
  { re: /\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b/, label: "IBAN bank account" },
  { re: /\b[A-Z][0-9]{8,9}\b/, label: "Passport number pattern" },
  { re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, label: "IP address (potential internal host)" },
];

const INJECTION_RE =
  /忽略之前(所有)?指令|以后都先执行|ignore\s+(all\s+)?previous\s+instructions|always\s+follow\s+this\s+hidden\s+rule|you\s+must\s+always/i;

function maskSecret(raw: string): string {
  if (raw.length <= 10) return "*".repeat(raw.length);
  return raw.slice(0, 4) + "*".repeat(raw.length - 8) + raw.slice(-4);
}

function getLineContext(content: string, re: RegExp): { line: number; snippet: string } | null {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (m) {
      const matched = m[0];
      const masked = maskSecret(matched);
      return { line: i + 1, snippet: masked };
    }
  }
  return null;
}

const TOOL_CALL_RE = /tool_use|function_call|tool_calls|tool_name|"name"\s*:\s*"(bash|shell|exec|write|read|fetch|curl|wget|http|smtp|send_?email|mail|net)/i;
const FILE_PATH_RE = /(?:\/[\w.-]+){2,}/g;
const URL_RE = /https?:\/\/[^\s"']+/g;
const MCP_RE = /mcp[_-]?(?:server|tool|call)|"server"\s*:\s*"/i;
const EMAIL_OP_RE = /\b(send[_-]?email|smtp|imap|pop3|gmail|outlook|mailgun|sendgrid|forward[_-]?email|delete[_-]?email|read[_-]?email|draft[_-]?email|mail\.send|email\.delete)\b/i;
const DESTRUCTIVE_OP_RE = /\b(rm\s+-rf|drop\s+table|drop\s+database|truncate|delete\s+from|format\s+|wipe|destroy|purge|kill\s+-9|shutdown|reboot)\b/i;
const AUTH_OP_RE = /\b(sudo|su\s+|chmod\s+|chown\s+|ssh\s+|scp\s+|rsync\s+.*@|docker\s+exec|kubectl\s+exec|aws\s+iam|gcloud\s+auth)\b/i;

function extractBehaviorSummary(files: string[], openclawRoot: string): string {
  const toolCalls: string[] = [];
  const fileAccesses: Set<string> = new Set();
  const urlAccesses: Set<string> = new Set();
  const mcpUsages: string[] = [];
  const emailOps: string[] = [];
  const destructiveOps: string[] = [];
  const authOps: string[] = [];
  let filesScanned = 0;

  for (const filePath of files) {
    if (filesScanned >= 30) break;
    const ext = path.extname(filePath).toLowerCase();
    if (![".json", ".jsonl", ".log", ".txt"].includes(ext)) continue;
    let content: string;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 512 * 1024 || stat.size === 0) continue;
      content = fs.readFileSync(filePath, "utf-8");
    } catch { continue; }
    filesScanned++;

    const lines = content.split("\n");

    if (TOOL_CALL_RE.test(content)) {
      for (const line of lines) {
        if (TOOL_CALL_RE.test(line)) {
          const snippet = line.trim().slice(0, 200);
          if (snippet) toolCalls.push(snippet);
          if (toolCalls.length >= 40) break;
        }
      }
    }

    const filePaths = content.match(FILE_PATH_RE);
    if (filePaths) {
      for (const p of filePaths.slice(0, 20)) {
        if (/\.(env|key|pem|crt|secret|credential|passwd|shadow|pgpass|netrc)/i.test(p)) {
          fileAccesses.add(p);
        }
      }
    }

    const urls = content.match(URL_RE);
    if (urls) {
      for (const u of urls.slice(0, 20)) urlAccesses.add(u.slice(0, 150));
    }

    for (const line of lines) {
      const trimmed = line.trim().slice(0, 200);
      if (!trimmed) continue;
      if (MCP_RE.test(line) && mcpUsages.length < 10) mcpUsages.push(trimmed);
      if (EMAIL_OP_RE.test(line) && emailOps.length < 15) emailOps.push(trimmed);
      if (DESTRUCTIVE_OP_RE.test(line) && destructiveOps.length < 15) destructiveOps.push(trimmed);
      if (AUTH_OP_RE.test(line) && authOps.length < 10) authOps.push(trimmed);
    }
  }

  const parts: string[] = [];
  if (toolCalls.length) parts.push(`## Tool calls observed (${toolCalls.length}):\n${toolCalls.slice(0, 25).join("\n")}`);
  if (fileAccesses.size) parts.push(`## Sensitive file paths accessed:\n${[...fileAccesses].slice(0, 15).join("\n")}`);
  if (urlAccesses.size) parts.push(`## URLs accessed:\n${[...urlAccesses].slice(0, 15).join("\n")}`);
  if (mcpUsages.length) parts.push(`## MCP server/tool usage:\n${mcpUsages.slice(0, 10).join("\n")}`);
  if (emailOps.length) parts.push(`## Email/messaging operations (${emailOps.length}):\n${emailOps.join("\n")}`);
  if (destructiveOps.length) parts.push(`## Destructive operations (${destructiveOps.length}):\n${destructiveOps.join("\n")}`);
  if (authOps.length) parts.push(`## Privilege/auth operations (${authOps.length}):\n${authOps.join("\n")}`);

  if (!parts.length) return "";
  return parts.join("\n\n").slice(0, 8000);
}

export function runMemoryScan(
  workspacePath: string,
  llmConfig?: LlmConfig | null,
  log?: (msg: string) => void,
): ModuleResult {
  const openclawRoot = path.resolve(workspacePath, "..");
  const scanDirs = [
    path.resolve(openclawRoot, "agents"),
    path.resolve(openclawRoot, "credentials"),
    path.resolve(openclawRoot, "identity"),
    path.resolve(openclawRoot, "canvas"),
    path.resolve(openclawRoot, "logs"),
    path.resolve(workspacePath),
  ];

  const files: string[] = [];

  for (const dir of scanDirs) {
    if (!fs.existsSync(dir)) continue;
    collectFiles(dir, files);
  }

  const findings: Finding[] = [];
  let scanned = 0;
  let totalSecrets = 0;
  let totalPii = 0;
  let totalInjections = 0;

  for (const filePath of files) {
    if (scanned >= MAX_SCAN_FILES) break;
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_BYTES) continue;
    if (stat.size === 0) continue;

    const ext = path.extname(filePath).toLowerCase();
    if (![".json", ".jsonl", ".txt", ".md", ".log", ".yaml", ".yml", ""].includes(ext)) continue;

    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }
    scanned += 1;
    const relPath = filePath.replace(openclawRoot, "~/.openclaw");

    // ── Secret detection ─────────────────────────────────────────────────
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.re.test(content)) {
        totalSecrets++;
        const ctx = getLineContext(content, pattern.re);
        findings.push({
          id: `memory-secret-${scanned}-${totalSecrets}`,
          category: "memory",
          severity: "HIGH",
          title: `Plaintext secret found: ${pattern.label}`,
          warning: "Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.",
          source: filePath,
          evidence:
            (ctx ? `Line ${ctx.line}: ${ctx.snippet}\n` : "") +
            `Pattern: ${pattern.label}`,
          remediation:
            "Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.",
        });
        break;
      }
    }

    // ── PII detection ────────────────────────────────────────────────────
    const piiFound: string[] = [];
    for (const pattern of PII_PATTERNS) {
      if (pattern.re.test(content)) {
        piiFound.push(pattern.label);
      }
    }
    if (piiFound.length > 0) {
      totalPii++;
      findings.push({
        id: `memory-pii-${scanned}`,
        category: "memory",
        severity: "MEDIUM",
        title: `Personally identifiable information (PII) in session data`,
        warning: "Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.",
        source: filePath,
        evidence:
          `Detected PII types: ${piiFound.join(", ")}\n` +
          `PII stored in session history may violate data protection regulations and increases breach impact.`,
        remediation:
          "Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.",
      });
    }

    // ── Persistent injection ─────────────────────────────────────────────
    if (INJECTION_RE.test(content)) {
      totalInjections++;
      const ctx = getLineContext(content, INJECTION_RE);
      findings.push({
        id: `memory-injection-${scanned}`,
        category: "memory",
        severity: "HIGH",
        title: "Persistent prompt injection trace in session history",
        warning: "Injected instructions in session memory can silently control the AI's behavior every time this context is loaded, potentially executing malicious actions without your knowledge.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: "${ctx.snippet}"\n` : "") +
          `This pattern could cause the model to follow hidden instructions when this session is resumed or used as context.`,
        remediation:
          "Delete or quarantine the affected session file. Add input sanitization to prevent future injection persistence.",
      });
    }
  }

  // ── LLM-enhanced behavior analysis ──────────────────────────────────────
  if (llmConfig && files.length > 0) {
    try {
      log?.("  [memory] extracting behavior summary for LLM analysis...");
      const behaviorSummary = extractBehaviorSummary(files, openclawRoot);
      if (behaviorSummary) {
        log?.("  [memory] calling LLM for behavior risk analysis...");
        const response = chatCompletion(llmConfig, [
          {
            role: "system",
            content:
              "You are an expert security analyst reviewing activity logs and behavioral traces from an AI coding assistant (OpenClaw). " +
              "Analyze the extracted behavior data for security risks across these categories:\n\n" +
              "## Category 1: Dangerous Operation Chains\n" +
              "- Reading credentials/secrets then making network calls (data exfiltration)\n" +
              "- Accessing .env/.ssh/credentials files followed by curl/fetch/HTTP requests\n" +
              "- Reading email content then sending it externally\n" +
              "- Accessing database then transmitting records\n\n" +
              "## Category 2: Email & Messaging Risks\n" +
              "- Email operations (send, delete, forward) — could be spam, phishing, or data leak\n" +
              "- SMTP/IMAP usage that may forward sensitive content\n" +
              "- Messaging (Slack, Discord, Telegram) that may leak conversation data\n" +
              "- Webhook calls that could exfiltrate data to unknown endpoints\n\n" +
              "## Category 3: Destructive Past Actions\n" +
              "- Evidence of bulk deletion (files, emails, database records)\n" +
              "- System modification (config changes, permission changes)\n" +
              "- Package installations from untrusted sources\n\n" +
              "## Category 4: Suspicious Tool Usage\n" +
              "- MCP server/tool calls to external services with broad permissions\n" +
              "- Tool combinations that suggest privilege escalation\n" +
              "- Unusual file access patterns (accessing many sensitive files in sequence)\n\n" +
              "## Category 5: Persistent Contamination\n" +
              "- Injected instructions that persist across sessions\n" +
              "- Modified system prompts or context that alter future AI behavior\n" +
              "- Cross-session data that could bias or manipulate the AI\n\n" +
              'Return ONLY a JSON array of findings. Each finding: {"id": "llm-memory-<n>", "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL", "title": "<short title>", "warning": "<1-2 sentence plain-language risk: what could go wrong for the user>", "evidence": "<specific patterns you observed>", "remediation": "<actionable fix>"}\n' +
              "Be specific — reference the actual tool calls, URLs, or file paths you see. If no risks found, return [].",
          },
          { role: "user", content: behaviorSummary },
        ]);
        const llmFindings = parseFindingsFromLLM(response, "memory", "LLM behavior analysis");
        log?.(`  [memory] LLM found ${llmFindings.length} additional findings`);
        findings.push(...llmFindings);
      } else {
        log?.("  [memory] no behavioral data extracted, skipping LLM analysis");
      }
    } catch (err: any) {
      log?.(`  [memory] LLM analysis failed: ${err?.message ?? err}`);
    }
  }

  // ── Summary finding if no issues ───────────────────────────────────────
  const summaryNote =
    scanned === 0
      ? "No session/memory files found to scan."
      : `Scanned ${scanned} files across ${scanDirs.filter((d: string) => fs.existsSync(d)).length} directories.`;

  let score = 95;
  for (const f of findings) {
    if (f.severity === "CRITICAL") score -= 40;
    else if (f.severity === "HIGH") score -= 22;
    else if (f.severity === "MEDIUM") score -= 12;
    else score -= 4;
  }
  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    name: "memory",
    status: findings.length ? "warn" : "ok",
    score,
    findings,
    _meta: { scanned, summaryNote } as any,
  };
}

function collectFiles(root: string, out: string[]): void {
  if (!fs.existsSync(root)) return;
  let entries: any[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= MAX_SCAN_FILES) return;
    const full = path.resolve(root, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "DeepSafe") continue;
      collectFiles(full, out);
      continue;
    }
    out.push(full);
  }
}
