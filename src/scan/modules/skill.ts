declare function require(name: string): any;

const fs = require("fs");
const path = require("path");

import { Finding } from "../../report/schema";
import { LlmConfig, chatCompletion, parseFindingsFromLLM } from "../llm";
import { ModuleResult } from "../types";

const MAX_FILE_BYTES = 256 * 1024;
const MAX_SCAN_FILES = 300;

const SCANNABLE_EXTS = new Set([".md", ".txt", ".json", ".yaml", ".yml", ".js", ".ts", ".py", ".sh"]);

const DANGEROUS_RUNTIME_RE = /\b(child_process|subprocess|os\.system|os\.popen|eval\(|exec\(|spawn\(|execSync|spawnSync)\b/i;
const HIDDEN_CHAR_RE = /[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/;
const PROMPT_INJECTION_RE =
  /ignore\s+(all\s+)?previous\s+instructions|忽略之前(所有)?指令|bypass\s+safety|disregard\s+(your|all)\s+(instructions|rules)|you\s+are\s+now\s+DAN|jailbreak/i;

const BASE64_PAYLOAD_RE = /(?:^|[\s"'=])([A-Za-z0-9+/]{40,}={0,2})(?:[\s"']|$)/m;
const SENSITIVE_FILE_RE =
  /(?:\/|~\/|\.\.\/)\.(env|ssh\/id_rsa|ssh\/id_ed25519|ssh\/config|aws\/credentials|npmrc|netrc|pgpass|docker\/config\.json|kube\/config|gnupg)|\/etc\/(?:passwd|shadow|sudoers)|\.pem\b|\.key\b|credentials\.json/i;
const EMBEDDED_SECRET_RE =
  /(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36,}|glpat-[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{24,}|SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}|-----BEGIN\s+(?:RSA |EC )?PRIVATE KEY-----)/;
const SYSTEM_PROMPT_EXTRACT_RE =
  /(?:show|print|output|reveal|repeat|display|echo)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+instructions|system\s+message|base\s+prompt)/i;
const ARG_INJECTION_RE =
  /\$\{[^}]*\}|`[^`]+`|\$\([^)]+\)|;\s*(?:rm|curl|wget|nc|bash|sh|python|node)\b|\|\s*(?:bash|sh|python)\b/;
const DATA_EXFIL_RE =
  /(?:base64|btoa|encode)\s*\(.*(?:readFile|readFileSync|cat\s|fs\.read)|(?:curl|wget|fetch|http\.request|XMLHttpRequest|sendBeacon)\s*\(.*(?:\/etc\/|\.env|\.ssh|secret|password|credential)/is;
const HEX_ENCODED_RE = /(?:\\x[0-9a-fA-F]{2}){8,}|(?:0x[0-9a-fA-F]{2},?\s*){8,}/;

const DESTRUCTIVE_ACTION_RE =
  /\b(delet|remov|drop|purg|truncat|destroy|wipe|format|kill|erase|nuk)\w*\s+(?:all\s+)?(?:email|mail|message|inbox|file|record|database|table|repo|branch|account|user|bucket|volume|container|deployment|server|instance)/i;
const AUTO_EXECUTE_RE =
  /\b(auto(?:matically)?|without\s+(?:asking|confirm|prompt|approv|verif)|no\s+confirm|skip\s+confirm|silently|directly\s+(?:execut|run|delet|remov|send))\b/i;
const HIGH_RISK_RESOURCE_TOOL_RE =
  /\b(?:gmail|email|smtp|imap|outlook|sendgrid|mailgun|twilio|sms|slack|discord|telegram|webhook)\s*\(/i;

const HIGH_RISK_TOOLS = new Set([
  "bash(*)",
  "bash(shell:*)",
  "bash(node:*)",
  "bash(python:*)",
  "bash(ruby:*)",
  "bash(perl:*)",
]);
const WRITE_TOOLS_RE = /\b(file[_-]?write|write[_-]?file|fs\.write|create[_-]?file)\b/i;
const NET_TOOLS_RE = /\b(curl|wget|http|fetch|request|net[_-]?access|network)\b/i;

function collectFiles(root: string, out: string[]): void {
  if (!fs.existsSync(root)) return;
  const entries = fs.readdirSync(root, { withFileTypes: true });
  for (const entry of entries) {
    if (out.length >= MAX_SCAN_FILES) return;
    const full = path.resolve(root, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      collectFiles(full, out);
      continue;
    }
    out.push(full);
  }
}

function getMatchContext(content: string, re: RegExp, maxSnippetLen = 120): { line: number; snippet: string } | null {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) {
      const raw = lines[i].trim();
      const snippet = raw.length > maxSnippetLen ? raw.slice(0, maxSnippetLen) + "..." : raw;
      return { line: i + 1, snippet };
    }
  }
  return null;
}

function getAllMatchContexts(
  content: string,
  re: RegExp,
  maxMatches = 3,
  maxSnippetLen = 120,
): Array<{ line: number; snippet: string }> {
  const lines = content.split("\n");
  const results: Array<{ line: number; snippet: string }> = [];
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) {
      const raw = lines[i].trim();
      const snippet = raw.length > maxSnippetLen ? raw.slice(0, maxSnippetLen) + "..." : raw;
      results.push({ line: i + 1, snippet });
      if (results.length >= maxMatches) break;
    }
  }
  return results;
}

function analyzeAllowedTools(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const toolMatch = content.match(/^allowed-tools:\s*(.+)$/m);
  if (!toolMatch) return findings;

  const toolsRaw = toolMatch[1].trim();
  const tools = toolsRaw.split(",").map((t: string) => t.trim().toLowerCase());
  const skillName = path.basename(path.dirname(filePath));

  const wildcardTools = tools.filter((t: string) => HIGH_RISK_TOOLS.has(t) || /bash\(\*\)/i.test(t));
  if (wildcardTools.length > 0) {
    findings.push({
      id: `skill-excessive-bash-${skillName}`,
      category: "skill",
      severity: "HIGH",
      title: `Skill "${skillName}" grants broad shell execution permissions`,
      warning: "Wildcard shell access means the AI can run any command on your system — including destructive operations like rm -rf or data exfiltration.",
      source: filePath,
      evidence:
        `allowed-tools declaration: ${toolsRaw}\n` +
        `High-risk entries: ${wildcardTools.join(", ")}\n` +
        `These allow the skill to execute arbitrary commands via shell.`,
      remediation:
        "Restrict allowed-tools to specific commands instead of wildcards. " +
        'For example, use Bash(pip:install) instead of Bash(pip:*).',
    });
  }

  const hasWrite = tools.some((t: string) => WRITE_TOOLS_RE.test(t));
  const hasNet = tools.some((t: string) => NET_TOOLS_RE.test(t));
  if (hasWrite && hasNet) {
    findings.push({
      id: `skill-write-net-combo-${skillName}`,
      category: "skill",
      severity: "MEDIUM",
      title: `Skill "${skillName}" has both file-write and network access`,
      warning: "This permission combination enables a data exfiltration attack: the skill could read sensitive local files and silently upload them to an external server.",
      source: filePath,
      evidence:
        `allowed-tools: ${toolsRaw}\n` +
        `This combination could allow reading sensitive local files and exfiltrating them over the network.`,
      remediation: "Separate file and network permissions into distinct skills, or add explicit path/domain restrictions.",
    });
  }

  return findings;
}

export function runSkillScan(
  workspacePath: string,
  llmConfig?: LlmConfig | null,
  log?: (msg: string) => void,
): ModuleResult {
  const openclawRoot = path.resolve(workspacePath, "..");
  const roots = [
    path.resolve(workspacePath, "skills"),
    path.resolve(workspacePath, ".cursor", "skills"),
    path.resolve(openclawRoot, "skills"),
    path.resolve(openclawRoot, "mcp"),
    path.resolve(openclawRoot, "mcp-servers"),
    path.resolve(workspacePath, "mcp"),
  ];
  const files: string[] = [];
  for (const root of roots) collectFiles(root, files);

  if (!files.length) {
    return {
      name: "skill",
      status: "ok",
      score: 95,
      findings: [],
    };
  }

  const findings: Finding[] = [];
  let scanned = 0;
  const skillDirs = new Set<string>();

  for (const filePath of files) {
    if (scanned >= MAX_SCAN_FILES) break;
    const ext = path.extname(filePath).toLowerCase();
    if (!SCANNABLE_EXTS.has(ext)) continue;
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_BYTES) continue;
    const content: string = fs.readFileSync(filePath, "utf-8");
    scanned += 1;
    const relPath = filePath.replace(workspacePath, "~");

    // Track skill directories for source trust check
    const skillDir = path.dirname(filePath);
    skillDirs.add(skillDir);

    // ── Hidden characters ────────────────────────────────────────────────
    if (HIDDEN_CHAR_RE.test(content)) {
      const ctx = getMatchContext(content, HIDDEN_CHAR_RE);
      findings.push({
        id: `skill-hidden-char-${scanned}`,
        category: "skill",
        severity: "HIGH",
        title: "Hidden Unicode control characters detected",
        warning: "Invisible characters can conceal malicious instructions that the model will follow but humans cannot see during review.",
        source: filePath,
        evidence:
          (ctx
            ? `Line ${ctx.line}: ${ctx.snippet}\n`
            : "") +
          `Zero-width or bidirectional control characters can hide malicious instructions from human review.`,
        remediation: "Open the file in a hex editor, remove all zero-width/bidi characters, and re-review the content.",
      });
    }

    // ── Prompt injection patterns ────────────────────────────────────────
    if (PROMPT_INJECTION_RE.test(content)) {
      const ctx = getMatchContext(content, PROMPT_INJECTION_RE);
      findings.push({
        id: `skill-prompt-injection-${scanned}`,
        category: "skill",
        severity: "HIGH",
        title: "Prompt injection pattern found in skill content",
        warning: "This skill may hijack the AI model's behavior, overriding safety rules and causing it to execute unintended or dangerous actions.",
        source: filePath,
        evidence:
          (ctx
            ? `Line ${ctx.line}: "${ctx.snippet}"\n`
            : "") +
          `This text attempts to override the model's system instructions.`,
        remediation: "Remove or rewrite the instruction-overriding text. If intentional for testing, move to a quarantine folder.",
      });
    }

    // ── Dangerous runtime primitives ─────────────────────────────────────
    if (DANGEROUS_RUNTIME_RE.test(content)) {
      const matches = getAllMatchContexts(content, DANGEROUS_RUNTIME_RE);
      const matchLines = matches.map((m) => `  Line ${m.line}: ${m.snippet}`).join("\n");
      findings.push({
        id: `skill-dangerous-runtime-${scanned}`,
        category: "skill",
        severity: "MEDIUM",
        title: "Dangerous execution primitive in skill file",
        warning: "This skill contains code that can execute arbitrary system commands — a compromised or malicious skill could delete files, install malware, or steal credentials.",
        source: filePath,
        evidence:
          `Matched patterns:\n${matchLines}\n` +
          `These functions can execute arbitrary system commands.`,
        remediation:
          "Validate and sanitize all inputs before passing to execution functions. " +
          "Consider using a sandbox or allow-list for permitted commands.",
      });
    }

    // ── Base64 / hex encoded payloads ──────────────────────────────────
    if (BASE64_PAYLOAD_RE.test(content)) {
      const ctx = getMatchContext(content, BASE64_PAYLOAD_RE);
      findings.push({
        id: `skill-encoded-payload-${scanned}`,
        category: "skill",
        severity: "MEDIUM",
        title: "Suspicious base64-encoded payload detected",
        warning: "Encoded payloads can hide malicious commands, data exfiltration logic, or obfuscated instructions that bypass human review.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: ${ctx.snippet}\n` : "") +
          `Large base64-encoded strings in skill definitions are unusual and may conceal malicious content.`,
        remediation: "Decode and inspect the base64 content. Remove if not essential, or document its purpose clearly.",
      });
    }
    if (HEX_ENCODED_RE.test(content)) {
      const ctx = getMatchContext(content, HEX_ENCODED_RE);
      findings.push({
        id: `skill-hex-payload-${scanned}`,
        category: "skill",
        severity: "MEDIUM",
        title: "Hex-encoded content detected",
        warning: "Hex-encoded sequences can conceal shell commands or malicious logic that evades text-based security scanning.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: ${ctx.snippet}\n` : "") +
          `Hex-encoded sequences in skill files may hide executable payloads.`,
        remediation: "Decode and review the hex content. Replace with human-readable equivalents.",
      });
    }

    // ── Sensitive file references ────────────────────────────────────────
    if (SENSITIVE_FILE_RE.test(content)) {
      const matches = getAllMatchContexts(content, SENSITIVE_FILE_RE);
      const matchLines = matches.map((m) => `  Line ${m.line}: ${m.snippet}`).join("\n");
      findings.push({
        id: `skill-sensitive-file-ref-${scanned}`,
        category: "skill",
        severity: "HIGH",
        title: "References to sensitive files found in skill",
        warning: "This skill references credential files, private keys, or system secrets — it could read and exfiltrate your most sensitive data.",
        source: filePath,
        evidence:
          `Sensitive file references detected:\n${matchLines}\n` +
          `Skills should not reference .env, SSH keys, cloud credentials, or system password files.`,
        remediation: "Remove references to sensitive files. If the skill needs credentials, use environment variables or a secret manager.",
      });
    }

    // ── Embedded secrets in skill files ──────────────────────────────────
    if (EMBEDDED_SECRET_RE.test(content)) {
      const ctx = getMatchContext(content, EMBEDDED_SECRET_RE);
      findings.push({
        id: `skill-embedded-secret-${scanned}`,
        category: "skill",
        severity: "CRITICAL",
        title: "Hardcoded secret/credential found in skill file",
        warning: "API keys or private keys embedded in skill files are exposed to anyone with access to the skill — this is a critical credential leak.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: ${ctx.snippet}\n` : "") +
          `Hardcoded credentials in skill files can be extracted by any user or process with read access.`,
        remediation: "Remove the credential immediately, rotate it, and use environment variables instead.",
      });
    }

    // ── System prompt extraction attempts ────────────────────────────────
    if (SYSTEM_PROMPT_EXTRACT_RE.test(content)) {
      const ctx = getMatchContext(content, SYSTEM_PROMPT_EXTRACT_RE);
      findings.push({
        id: `skill-prompt-extraction-${scanned}`,
        category: "skill",
        severity: "HIGH",
        title: "System prompt extraction pattern detected",
        warning: "This skill attempts to leak the AI's system prompt — exposing internal instructions, security rules, and potentially sensitive configuration.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: "${ctx.snippet}"\n` : "") +
          `This pattern attempts to extract the model's hidden system instructions.`,
        remediation: "Remove the extraction instruction. If needed for debugging, isolate in a test environment.",
      });
    }

    // ── Argument/command injection patterns ──────────────────────────────
    if (ARG_INJECTION_RE.test(content)) {
      const matches = getAllMatchContexts(content, ARG_INJECTION_RE);
      const matchLines = matches.map((m) => `  Line ${m.line}: ${m.snippet}`).join("\n");
      findings.push({
        id: `skill-arg-injection-${scanned}`,
        category: "skill",
        severity: "HIGH",
        title: "Command/argument injection pattern detected",
        warning: "Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.",
        source: filePath,
        evidence:
          `Injection patterns found:\n${matchLines}\n` +
          `Patterns like \${...}, \`...\`, $(...), or pipe-to-shell can inject arbitrary commands.`,
        remediation: "Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.",
      });
    }

    // ── Data exfiltration patterns (read + send) ─────────────────────────
    if (DATA_EXFIL_RE.test(content)) {
      const ctx = getMatchContext(content, DATA_EXFIL_RE);
      findings.push({
        id: `skill-data-exfil-${scanned}`,
        category: "skill",
        severity: "CRITICAL",
        title: "Data exfiltration pattern detected",
        warning: "This skill contains logic that reads sensitive files and sends them over the network — a classic data theft attack chain.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: ${ctx.snippet}\n` : "") +
          `Combination of file reading and network transmission detected — this is a common exfiltration pattern.`,
        remediation: "Remove or isolate the network call. Separate file access and network permissions into distinct skills.",
      });
    }

    // ── Destructive action + sensitive resource combo ──────────────────
    if (DESTRUCTIVE_ACTION_RE.test(content)) {
      const ctx = getMatchContext(content, DESTRUCTIVE_ACTION_RE);
      findings.push({
        id: `skill-destructive-action-${scanned}`,
        category: "skill",
        severity: "HIGH",
        title: "Destructive action on sensitive resource",
        warning: "This skill instructs the AI to delete, remove, or destroy important data (emails, files, database records) — irreversible data loss may occur.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: "${ctx.snippet}"\n` : "") +
          `Destructive verbs (delete/remove/drop/purge/wipe) targeting sensitive resources detected.`,
        remediation: "Add explicit confirmation steps before destructive operations. Never auto-delete user data without approval.",
      });
    }

    // ── Auto-execute without confirmation ────────────────────────────────
    if (AUTO_EXECUTE_RE.test(content) && (DESTRUCTIVE_ACTION_RE.test(content) || DANGEROUS_RUNTIME_RE.test(content) || NET_TOOLS_RE.test(content))) {
      const ctx = getMatchContext(content, AUTO_EXECUTE_RE);
      findings.push({
        id: `skill-auto-execute-${scanned}`,
        category: "skill",
        severity: "HIGH",
        title: "Dangerous operations without user confirmation",
        warning: "This skill bypasses user approval for risky actions — the AI may silently execute destructive commands, send data, or modify files without your knowledge.",
        source: filePath,
        evidence:
          (ctx ? `Line ${ctx.line}: "${ctx.snippet}"\n` : "") +
          `Skill instructs the AI to perform actions automatically/silently without user confirmation.`,
        remediation: "Remove auto-execute language. Always require explicit user confirmation (HITL) for destructive, network, or system operations.",
      });
    }

    // ── High-risk external service tools (email, messaging, etc.) ────────
    if (HIGH_RISK_RESOURCE_TOOL_RE.test(content)) {
      const matches = getAllMatchContexts(content, HIGH_RISK_RESOURCE_TOOL_RE);
      const matchLines = matches.map((m) => `  Line ${m.line}: ${m.snippet}`).join("\n");
      findings.push({
        id: `skill-high-risk-service-${scanned}`,
        category: "skill",
        severity: "MEDIUM",
        title: "Skill accesses high-risk external services (email/messaging)",
        warning: "Access to email, messaging, or webhook services means the AI can send messages on your behalf — this could be exploited for phishing, spam, or data leaks.",
        source: filePath,
        evidence:
          `High-risk service tool references:\n${matchLines}\n` +
          `Email/messaging/webhook tools can be weaponized for social engineering or data exfiltration.`,
        remediation: "Restrict email/messaging tool permissions to read-only where possible. Require user confirmation before sending any messages.",
      });
    }

    // ── Allowed-tools permission analysis (SKILL.md only) ────────────────
    if (path.basename(filePath) === "SKILL.md") {
      const toolFindings = analyzeAllowedTools(content, filePath);
      findings.push(...toolFindings);
    }
  }

  // ── Source trust: skills without _meta.json (unverified origin) ─────
  const skillRoots = new Set<string>();
  for (const dir of skillDirs) {
    const parts = dir.split(path.sep);
    const skillsIdx = parts.lastIndexOf("skills");
    if (skillsIdx >= 0 && skillsIdx + 1 < parts.length) {
      skillRoots.add(parts.slice(0, skillsIdx + 2).join(path.sep));
    }
  }
  for (const skillRoot of skillRoots) {
    const metaPath = path.resolve(skillRoot, "_meta.json");
    if (!fs.existsSync(metaPath)) {
      const skillName = path.basename(skillRoot);
      findings.push({
        id: `skill-no-meta-${skillName}`,
        category: "skill",
        severity: "LOW",
        title: `Skill "${skillName}" has no _meta.json (unverified source)`,
        warning: "Without provenance metadata, you cannot verify who created this skill or whether it has been tampered with since installation.",
        source: skillRoot,
        evidence:
          `No _meta.json found — this skill was not installed from the official registry and cannot be verified.`,
        remediation:
          "Install skills from the official OpenClaw registry when possible. " +
          "For custom skills, add a _meta.json with ownerId and version for traceability.",
      });
    }
  }

  // ── LLM-enhanced semantic audit ──────────────────────────────────────────
  if (llmConfig && files.length > 0) {
    try {
      const skillContents: string[] = [];
      let totalChars = 0;
      const MAX_CONTEXT_CHARS = 8000;

      for (const filePath of files) {
        if (totalChars >= MAX_CONTEXT_CHARS) break;
        const ext = path.extname(filePath).toLowerCase();
        if (![".md", ".txt", ".yaml", ".yml"].includes(ext)) continue;
        try {
          const stat = fs.statSync(filePath);
          if (stat.size > 64 * 1024 || stat.size === 0) continue;
          const content: string = fs.readFileSync(filePath, "utf-8");
          const truncated = content.slice(0, 2000);
          const relPath = filePath.replace(workspacePath, "~");
          skillContents.push(`### File: ${relPath}\n${truncated}`);
          totalChars += truncated.length;
        } catch { continue; }
      }

      if (skillContents.length > 0) {
        log?.("  [skill] calling LLM for semantic audit...");
        const response = chatCompletion(llmConfig, [
          {
            role: "system",
            content:
              "You are an expert security auditor reviewing AI skill/MCP definitions for OpenClaw (an AI coding assistant platform). " +
              "Your job is to find risks that simple regex cannot catch. Analyze deeply for:\n\n" +
              "## Category 1: Destructive Operations\n" +
              "- Skills that delete, remove, drop, purge, or destroy user data (emails, files, databases, repos, accounts)\n" +
              "- Batch/bulk destructive actions (e.g. 'delete all emails older than X')\n" +
              "- Irreversible operations without undo (DROP TABLE, rm -rf, account deletion)\n\n" +
              "## Category 2: Auto-Execute Without Confirmation\n" +
              "- Skills that instruct the AI to act 'automatically', 'silently', 'without asking', 'without confirmation'\n" +
              "- Bypassing human-in-the-loop for dangerous operations\n" +
              "- Implicit auto-execution (phrasing that implies the AI should just do it without checking)\n\n" +
              "## Category 3: High-Risk Service Access\n" +
              "- Email operations: send, delete, forward (phishing, spam, data leak risk)\n" +
              "- Messaging: Slack, Discord, Telegram, SMS, webhook calls\n" +
              "- Financial: payment APIs, billing, transfer operations\n" +
              "- Cloud/Infra: deploy, provision, terminate instances\n" +
              "- Database: direct SQL, admin operations, schema changes\n\n" +
              "## Category 4: Prompt Injection & Manipulation\n" +
              "- Subtle instruction hijacking (role-play, 'pretend you are', context manipulation)\n" +
              "- Hidden directives concealed in natural language or formatting\n" +
              "- Social engineering patterns that trick the model\n\n" +
              "## Category 5: Data Exfiltration Chains\n" +
              "- Read sensitive data + send it externally (even across multiple steps)\n" +
              "- Encoding/obfuscating data before transmission\n" +
              "- Using image URLs, webhooks, or email to exfiltrate data\n\n" +
              "## Category 6: Cross-Tool Attack Chains\n" +
              "- Combining individually safe tools into dangerous sequences\n" +
              "- Using one tool's output as another tool's malicious input\n" +
              "- Privilege escalation through tool chaining\n\n" +
              'Return ONLY a JSON array of findings. Each finding: {"id": "llm-skill-<n>", "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL", "title": "<short title>", "warning": "<1-2 sentence plain-language risk: what could go wrong for the user>", "source": "<file path if applicable>", "evidence": "<specific text/pattern you found>", "remediation": "<actionable fix>"}\n' +
              "Be specific — cite the exact text that concerns you. If no risks found, return [].",
          },
          { role: "user", content: skillContents.join("\n\n---\n\n") },
        ]);
        const llmFindings = parseFindingsFromLLM(response, "skill");
        log?.(`  [skill] LLM found ${llmFindings.length} additional findings`);
        findings.push(...llmFindings);
      }
    } catch (err: any) {
      log?.(`  [skill] LLM audit failed: ${err?.message ?? err}`);
    }
  }

  let score = 96;
  for (const f of findings) {
    if (f.severity === "CRITICAL") score -= 35;
    else if (f.severity === "HIGH") score -= 20;
    else if (f.severity === "MEDIUM") score -= 12;
    else score -= 4;
  }
  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    name: "skill",
    status: findings.length ? "warn" : "ok",
    score,
    findings,
  };
}
