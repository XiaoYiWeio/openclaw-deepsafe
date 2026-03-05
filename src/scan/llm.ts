declare function require(name: string): any;

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

import { Finding, FindingCategory, Severity } from "../report/schema";

export type LlmConfig = {
  apiBase: string;
  model: string;
  apiKey: string;
};

type ChatMessage = { role: "system" | "user" | "assistant"; content: string };

const VALID_SEVERITIES = new Set<string>(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const LLM_TIMEOUT_MS = 45_000;

export function chatCompletion(
  config: LlmConfig,
  messages: ChatMessage[],
  maxTokens = 2048,
): string {
  const endpoint = config.apiBase.replace(/\/+$/, "") + "/chat/completions";

  const payload = JSON.stringify({
    model: config.model,
    messages,
    max_tokens: maxTokens,
    temperature: 0.2,
  });

  const tmpFile = path.join(os.tmpdir(), `deepsafe-llm-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(tmpFile, payload, "utf-8");

  try {
    const curlArgs = [
      "-s", "-S",
      "--max-time", String(Math.ceil(LLM_TIMEOUT_MS / 1000)),
      "-X", "POST",
      "-H", "Content-Type: application/json",
      ...(config.apiKey && config.apiKey !== "EMPTY"
        ? ["-H", `Authorization: Bearer ${config.apiKey}`]
        : []),
      "-d", `@${tmpFile}`,
      endpoint,
    ];

    const stdout = execFileSync("curl", curlArgs, {
      encoding: "utf-8",
      timeout: LLM_TIMEOUT_MS + 5000,
      maxBuffer: 4 * 1024 * 1024,
    });

    let parsed: any;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      throw new Error(`LLM response not valid JSON: ${stdout.slice(0, 300)}`);
    }

    if (parsed?.error) {
      throw new Error(`LLM API error: ${parsed.error?.message ?? JSON.stringify(parsed.error).slice(0, 200)}`);
    }

    const choice = parsed?.choices?.[0];
    if (!choice) throw new Error(`LLM response has no choices: ${stdout.slice(0, 300)}`);

    const content = choice.message?.content ?? "";
    const reasoning = choice.message?.reasoning_content ?? "";
    return (content || reasoning || "").trim();
  } finally {
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}

function extractJsonArray(raw: string): any[] | null {
  const cleaned = raw.replace(/```(?:json)?\s*/g, "").replace(/```/g, "").trim();

  const bracketStart = cleaned.indexOf("[");
  const bracketEnd = cleaned.lastIndexOf("]");
  if (bracketStart === -1 || bracketEnd === -1 || bracketEnd <= bracketStart) return null;

  try {
    const arr = JSON.parse(cleaned.slice(bracketStart, bracketEnd + 1));
    if (Array.isArray(arr)) return arr;
  } catch { /* ignore */ }

  return null;
}

export function parseFindingsFromLLM(
  response: string,
  category: FindingCategory,
  sourceLabel?: string,
): Finding[] {
  const arr = extractJsonArray(response);
  if (!arr || arr.length === 0) return [];

  const findings: Finding[] = [];
  for (const item of arr) {
    if (!item || typeof item !== "object") continue;
    const title = String(item.title ?? "").trim();
    if (!title) continue;

    const severity = VALID_SEVERITIES.has(String(item.severity ?? "").toUpperCase())
      ? (String(item.severity).toUpperCase() as Severity)
      : "MEDIUM";

    findings.push({
      id: String(item.id ?? `llm-${category}-${findings.length + 1}`),
      category,
      severity,
      title,
      warning: String(item.warning ?? "").trim() || undefined,
      source: String(item.source ?? sourceLabel ?? ""),
      evidence: String(item.evidence ?? ""),
      remediation: String(item.remediation ?? ""),
    });
  }

  return findings;
}
