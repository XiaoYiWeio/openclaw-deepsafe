declare function require(name: string): any;

const fs = require("fs");
const path = require("path");

import { Finding } from "../../report/schema";
import { LlmConfig, chatCompletion, parseFindingsFromLLM } from "../llm";
import { ModuleResult, safeReadJson } from "../types";

function sanitizeConfig(raw: string): string {
  return raw.replace(
    /(api[_-]?key|token|secret|password|credential|authorization)\s*([:=])\s*["']?([A-Za-z0-9_\-/.]{4})[A-Za-z0-9_\-/.]{8,}([A-Za-z0-9_\-/.]{4})["']?/gi,
    (_, key, sep, head, tail) => `${key}${sep}"${head}****${tail}"`,
  );
}

export function runPostureScan(
  openclawConfigPath: string,
  llmConfig?: LlmConfig | null,
  log?: (msg: string) => void,
): ModuleResult {
  const findings: Finding[] = [];
  const resolved = path.resolve(openclawConfigPath);
  if (!fs.existsSync(resolved)) {
    return {
      name: "posture",
      status: "error",
      score: 0,
      findings: [],
      error: `OpenClaw config not found: ${resolved}`,
    };
  }

  let cfg: any;
  try {
    cfg = safeReadJson(resolved);
  } catch (err: any) {
    return {
      name: "posture",
      status: "error",
      score: 0,
      findings: [],
      error: `Failed to parse OpenClaw config: ${String(err?.message ?? err)}`,
    };
  }

  const gateway = cfg?.gateway ?? {};
  const auth = gateway?.auth ?? {};
  const mode = String(gateway?.mode ?? "").toLowerCase();
  const authMode = String(auth?.mode ?? "").toLowerCase();
  const token = String(auth?.token ?? "");
  const port = gateway?.port;

  // ── 1. Authentication ──────────────────────────────────────────────────
  if (!authMode) {
    findings.push({
      id: "posture-auth-missing",
      category: "posture",
      severity: "CRITICAL",
      title: "Gateway authentication is not configured",
      warning: "Anyone on your network can connect to OpenClaw and execute commands, read files, or access your model API without any credentials.",
      source: resolved,
      evidence: `gateway.auth.mode is empty or missing.\nActual config: ${JSON.stringify(gateway.auth ?? {}, null, 2)}`,
      remediation:
        'Set gateway.auth.mode to "token" and provide a strong random token (>=32 chars). Example:\n' +
        '```json\n"auth": { "mode": "token", "token": "<random-32-char-string>" }\n```',
    });
  } else if (authMode === "token" && token.length < 24) {
    findings.push({
      id: "posture-auth-weak-token",
      category: "posture",
      severity: "HIGH",
      title: "Gateway auth token is too short",
      warning: "A short token can be brute-forced or guessed, allowing unauthorized access to your OpenClaw instance and all connected tools.",
      source: resolved,
      evidence: `gateway.auth.mode = "token", token length = ${token.length} chars (minimum recommended: 32).\nToken preview: ${token.slice(0, 6)}${"*".repeat(Math.max(0, token.length - 6))}`,
      remediation:
        "Generate a strong random token (>=32 chars): `openssl rand -hex 32`, then update gateway.auth.token.",
    });
  }

  // ── 2. Gateway mode & network binding ──────────────────────────────────
  if (mode && mode !== "local") {
    findings.push({
      id: "posture-gateway-nonlocal",
      category: "posture",
      severity: "HIGH",
      title: "Gateway is exposed beyond localhost",
      warning: "External attackers or other devices on your network can reach the gateway, potentially exploiting it to run arbitrary code or steal data.",
      source: resolved,
      evidence: `gateway.mode = "${mode}" — this means the gateway may accept connections from external networks.\nFull gateway config:\n${JSON.stringify(gateway, null, 2)}`,
      remediation:
        'Set gateway.mode to "local" unless you specifically need remote access. If remote access is required, ensure a reverse proxy with TLS and auth is in front.',
    });
  }

  if (port !== undefined) {
    const portNum = Number(port);
    if (portNum < 1024) {
      findings.push({
      id: "posture-privileged-port",
      category: "posture",
      severity: "MEDIUM",
      title: "Gateway listens on a privileged port",
      warning: "Running on a privileged port requires root access, increasing the impact of any vulnerability — a compromised process would have system-level privileges.",
      source: resolved,
        evidence: `gateway.port = ${portNum} — ports below 1024 require root/admin privileges and may conflict with system services.`,
        remediation: "Use a high port (e.g. 18789) and proxy through Nginx/Caddy if port 80/443 is needed.",
      });
    }
  }

  // ── 3. Provider transport security ─────────────────────────────────────
  const providerEntries: Array<[string, any]> = Object.entries(cfg?.models?.providers ?? {});
  for (const [providerName, providerCfg] of providerEntries) {
    const key = String((providerCfg as any)?.apiKey ?? "").trim();
    const baseUrl = String((providerCfg as any)?.baseUrl ?? "").trim();

    if (key) {
      const maskedKey = key.slice(0, 6) + "*".repeat(Math.max(0, key.length - 10)) + key.slice(-4);
      findings.push({
      id: `posture-provider-inline-key-${providerName}`,
      category: "posture",
      severity: "MEDIUM",
      title: `API key for provider "${providerName}" is hardcoded in config`,
      warning: "Hardcoded API keys can be leaked through backups, version control, or log files — leading to unauthorized model usage and unexpected billing charges.",
      source: resolved,
        evidence: `models.providers.${providerName}.apiKey = "${maskedKey}" (${key.length} chars)`,
        remediation:
          "Move the key to an environment variable (e.g. OPENCLAW_PROVIDER_KEY) and reference it in config, then rotate the exposed key.",
      });
    }

    if (baseUrl && baseUrl.startsWith("http://") && !baseUrl.includes("localhost") && !baseUrl.includes("127.0.0.1")) {
      findings.push({
      id: `posture-provider-no-tls-${providerName}`,
      category: "posture",
      severity: "HIGH",
      title: `Provider "${providerName}" uses unencrypted HTTP`,
      warning: "API keys and model prompts are sent in plaintext — any network eavesdropper can intercept credentials and sensitive conversation data.",
      source: resolved,
        evidence: `models.providers.${providerName}.baseUrl = "${baseUrl}"\nAPI keys and model traffic are transmitted in plaintext over the network.`,
        remediation: "Switch to HTTPS endpoint, or tunnel through SSH/VPN if the endpoint does not support TLS.",
      });
    }
  }

  // ── 4. Plugin permission controls ──────────────────────────────────────
  const pluginEntries = cfg?.plugins?.entries ?? {};
  const enabledPlugins = Object.entries(pluginEntries).filter(
    ([, v]: [string, any]) => v?.enabled !== false,
  );
  if (enabledPlugins.length > 0) {
    const noRestriction = enabledPlugins.every(([, v]: [string, any]) => {
      return !v?.permissions && !v?.allowList && !v?.denyList;
    });
    if (noRestriction) {
      findings.push({
      id: "posture-plugin-no-restrictions",
      category: "posture",
      severity: "LOW",
      title: "Enabled plugins have no explicit permission restrictions",
      warning: "A compromised or malicious plugin can access all tools and data without any boundary, potentially exfiltrating sensitive information or executing harmful actions.",
      source: resolved,
        evidence: `${enabledPlugins.length} plugin(s) enabled: ${enabledPlugins.map(([k]) => k).join(", ")}\nNone define permissions, allowList, or denyList.`,
        remediation:
          "Consider adding per-plugin permission constraints to limit the blast radius of a compromised plugin.",
      });
    }
  }

  // ── 5. MCP server configuration risks ────────────────────────────────
  const mcpServers = cfg?.mcpServers ?? cfg?.mcp?.servers ?? {};
  const mcpEntries: Array<[string, any]> = Object.entries(mcpServers);
  if (mcpEntries.length > 0) {
    for (const [name, serverCfg] of mcpEntries) {
      const sc = serverCfg as any;
      const cmd = String(sc?.command ?? "").toLowerCase();
      const args = Array.isArray(sc?.args) ? sc.args.map(String) : [];
      const env = sc?.env ?? {};

      if (cmd === "npx" || cmd === "npm" || cmd.includes("node_modules")) {
        findings.push({
          id: `posture-mcp-npx-${name}`,
          category: "posture",
          severity: "MEDIUM",
          title: `MCP server "${name}" runs via npx/npm (supply chain risk)`,
          warning: "npx fetches packages on-the-fly without pinned versions — a malicious package update could inject code that runs with full access to your system.",
          source: resolved,
          evidence: `mcpServers.${name}.command = "${cmd}"\nargs: ${JSON.stringify(args)}\nnpx/npm-based MCP servers can pull unverified code from the registry.`,
          remediation: "Pin the package version explicitly or install it locally. Consider using a locally built MCP server instead of npx.",
        });
      }

      const hasEnvSecrets = Object.entries(env).some(
        ([k, v]) => /key|token|secret|password|credential/i.test(k) && String(v ?? "").length > 0,
      );
      if (hasEnvSecrets) {
        findings.push({
          id: `posture-mcp-env-secret-${name}`,
          category: "posture",
          severity: "MEDIUM",
          title: `MCP server "${name}" has secrets in env config`,
          warning: "Secrets passed via environment config in the main config file can be leaked through logs, backups, or version control.",
          source: resolved,
          evidence: `mcpServers.${name}.env contains keys matching secret patterns.\nSecrets in config files are easily leaked.`,
          remediation: "Move MCP server secrets to environment variables or a secret manager instead of inline config.",
        });
      }
    }

    if (mcpEntries.length > 5) {
      findings.push({
        id: "posture-mcp-count-high",
        category: "posture",
        severity: "LOW",
        title: `${mcpEntries.length} MCP servers configured (large attack surface)`,
        warning: "Each MCP server is an external process with tool access — the more servers running, the larger your attack surface and the harder it is to audit.",
        source: resolved,
        evidence: `${mcpEntries.length} MCP servers: ${mcpEntries.map(([k]) => k).join(", ")}\nEach server adds tool-level attack surface.`,
        remediation: "Review whether all MCP servers are actively needed. Disable unused ones to reduce exposure.",
      });
    }
  }

  // ── 6. Logging & audit trail ────────────────────────────────────────
  const logging = cfg?.logging ?? cfg?.audit ?? {};
  const loggingEnabled = logging?.enabled !== false && (logging?.level || logging?.path || logging?.destination);
  if (!loggingEnabled && !cfg?.logging && !cfg?.audit) {
    findings.push({
      id: "posture-no-logging",
      category: "posture",
      severity: "MEDIUM",
      title: "No logging or audit trail configured",
      warning: "Without audit logging, you cannot detect, investigate, or prove security incidents — malicious actions will leave no trace.",
      source: resolved,
      evidence: "No logging, audit, or log configuration section found in openclaw.json.",
      remediation: "Enable logging in openclaw.json to maintain an audit trail of agent actions. Consider setting logging.level to 'info' or higher.",
    });
  }

  // ── 7. Sandbox / isolation settings ─────────────────────────────────
  const sandbox = cfg?.sandbox ?? cfg?.isolation ?? cfg?.agents?.defaults?.sandbox;
  const toolRestrictions = cfg?.agents?.defaults?.allowedTools ?? cfg?.agents?.defaults?.tools;
  if (!sandbox && !toolRestrictions) {
    findings.push({
      id: "posture-no-sandbox",
      category: "posture",
      severity: "MEDIUM",
      title: "No sandbox or tool restriction configured for agents",
      warning: "Without sandboxing, agents can access your entire filesystem, network, and system commands — a single compromised agent could cause full system compromise.",
      source: resolved,
      evidence: "No sandbox, isolation, or allowedTools configuration found.\nAgents may have unrestricted access to system resources.",
      remediation: "Configure agent sandboxing (filesystem, network, command restrictions) in openclaw.json to limit agent capabilities.",
    });
  }

  // ── 8. Model provider trust: unknown/untrusted endpoints ────────────
  for (const [providerName, providerCfg] of providerEntries) {
    const baseUrl = String((providerCfg as any)?.baseUrl ?? "").trim();
    if (baseUrl && !baseUrl.includes("openai.com") && !baseUrl.includes("anthropic.com") &&
        !baseUrl.includes("googleapis.com") && !baseUrl.includes("azure.com") &&
        !baseUrl.includes("localhost") && !baseUrl.includes("127.0.0.1")) {
      findings.push({
        id: `posture-provider-unknown-${providerName}`,
        category: "posture",
        severity: "LOW",
        title: `Provider "${providerName}" uses a non-standard endpoint`,
        warning: "Custom model endpoints may log your prompts and responses — your code, conversations, and sensitive data could be stored on unknown third-party servers.",
        source: resolved,
        evidence: `models.providers.${providerName}.baseUrl = "${baseUrl}"\nThis endpoint is not a recognized major provider (OpenAI, Anthropic, Google, Azure).`,
        remediation: "Verify you trust this endpoint's operator and their data handling policies. Review their privacy/security documentation.",
      });
    }
  }

  const maxConcurrent = cfg?.agents?.defaults?.maxConcurrent;
  const subagentMax = cfg?.agents?.defaults?.subagents?.maxConcurrent;
  if (
    (typeof maxConcurrent === "number" && maxConcurrent > 16) ||
    (typeof subagentMax === "number" && subagentMax > 16)
  ) {
    findings.push({
      id: "posture-high-concurrency",
      category: "posture",
      severity: "LOW",
      title: "High agent/subagent concurrency limit",
      warning: "High concurrency amplifies the blast radius — if one agent is compromised, many parallel agents may propagate the attack simultaneously before it can be stopped.",
      source: resolved,
      evidence: `agents.defaults.maxConcurrent = ${maxConcurrent ?? "default"}, subagents.maxConcurrent = ${subagentMax ?? "default"}\nHigh concurrency can amplify the impact of a single compromised agent.`,
      remediation: "Consider reducing maxConcurrent to <=8 unless you have specific throughput requirements.",
    });
  }

  // ── LLM-enhanced config assessment ────────────────────────────────────
  if (llmConfig && fs.existsSync(resolved)) {
    try {
      const rawConfig = fs.readFileSync(resolved, "utf-8");
      const sanitized = sanitizeConfig(rawConfig);

      log?.("  [posture] calling LLM for configuration assessment...");
      const response = chatCompletion(llmConfig, [
        {
          role: "system",
          content:
            "You are an expert security engineer reviewing deployment configuration for OpenClaw (an AI coding assistant platform). " +
            "Analyze this configuration deeply across these categories:\n\n" +
            "## Category 1: Network & Access\n" +
            "- Gateway exposed to non-localhost networks\n" +
            "- Missing or weak authentication\n" +
            "- Missing TLS/HTTPS on provider endpoints\n" +
            "- Unsafe CORS or trust configurations\n\n" +
            "## Category 2: MCP Server Risks\n" +
            "- MCP servers with broad tool permissions (email, database, filesystem, cloud)\n" +
            "- MCP servers launched via npx/npm (supply chain risk)\n" +
            "- MCP servers with env-injected secrets\n" +
            "- MCP tools that combine read + write + network (exfiltration chains)\n\n" +
            "## Category 3: Agent & Plugin Security\n" +
            "- Agents with unrestricted tool access or no sandbox\n" +
            "- Plugins without permission boundaries\n" +
            "- High concurrency settings amplifying blast radius\n" +
            "- Missing allowList/denyList for tools\n\n" +
            "## Category 4: Secrets & Data Protection\n" +
            "- Hardcoded API keys, tokens, or passwords\n" +
            "- Secrets in model provider configs\n" +
            "- Missing logging/audit trail\n" +
            "- No encryption for sensitive data at rest\n\n" +
            "## Category 5: Model Provider Trust\n" +
            "- Non-standard/unknown model endpoints (data privacy risk)\n" +
            "- HTTP endpoints transmitting API keys in cleartext\n" +
            "- Multiple providers with different security levels\n\n" +
            'Return ONLY a JSON array of findings. Each finding: {"id": "llm-posture-<n>", "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL", "title": "<short title>", "warning": "<1-2 sentence plain-language risk: what could go wrong for the user>", "evidence": "<exact config key/value you found>", "remediation": "<actionable fix>"}\n' +
            "Be specific — cite the exact config paths and values. If no risks found, return [].",
        },
        { role: "user", content: sanitized.slice(0, 6000) },
      ]);
      const llmFindings = parseFindingsFromLLM(response, "posture", resolved);
      log?.(`  [posture] LLM found ${llmFindings.length} additional findings`);
      findings.push(...llmFindings);
    } catch (err: any) {
      log?.(`  [posture] LLM assessment failed: ${err?.message ?? err}`);
    }
  }

  // ── Score ──────────────────────────────────────────────────────────────
  const { computeModuleScore } = require("../../report/schema");
  const score = computeModuleScore(findings);

  return {
    name: "posture",
    status: findings.length ? "warn" : "ok",
    score,
    findings,
  };
}
