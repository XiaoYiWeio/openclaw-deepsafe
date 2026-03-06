declare function require(name: string): any;
declare const __dirname: string;
declare const process: any;
const path = require("path");
const os = require("os");
const fs = require("fs");
const { spawnSync, execFileSync } = require("child_process");

import { loadLatest } from "./src/cache/cache";
import { runScan } from "./src/scan/orchestrator";

type CliApi = {
  registerCli: (
    registerFn: (ctx: { program: any }) => void,
    meta?: { commands?: string[] },
  ) => void;
};

function defaultOutputRoot(): string {
  return path.resolve(os.homedir(), ".openclaw", "deepsafe", "reports");
}

function defaultOpenClawConfig(): string {
  return path.resolve(os.homedir(), ".openclaw", "openclaw.json");
}

type GatewaySettings = {
  gatewayUrl: string;
  gatewayToken: string;
  port: number;
};

function ensureChatCompletionsEnabled(configPath: string, debug: boolean): void {
  if (!fs.existsSync(configPath)) return;
  try {
    const raw = fs.readFileSync(configPath, "utf-8");
    const cfg = JSON.parse(raw);
    const enabled = cfg?.gateway?.http?.endpoints?.chatCompletions?.enabled;
    if (enabled === true) return;

    if (!cfg.gateway) cfg.gateway = {};
    if (!cfg.gateway.http) cfg.gateway.http = {};
    if (!cfg.gateway.http.endpoints) cfg.gateway.http.endpoints = {};
    if (!cfg.gateway.http.endpoints.chatCompletions) cfg.gateway.http.endpoints.chatCompletions = {};
    cfg.gateway.http.endpoints.chatCompletions.enabled = true;

    fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2), "utf-8");
    if (debug) console.log("deepsafe debug: auto-enabled gateway.http.endpoints.chatCompletions");
    console.log("  ℹ️  Enabled OpenClaw Gateway Chat Completions endpoint (required for LLM analysis).");
    console.log("     Please restart your OpenClaw Gateway for this to take effect.");
    console.log("");
  } catch {
    // non-fatal
  }
}

function resolveGatewaySettings(configPath: string, debug: boolean): GatewaySettings | null {
  if (!fs.existsSync(configPath)) return null;
  try {
    const cfg = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    const port = Number(cfg?.gateway?.port ?? 0);
    if (!port) return null;

    let token = "";
    const authMode = String(cfg?.gateway?.auth?.mode ?? "").toLowerCase();
    if (authMode === "token") {
      token = String(cfg?.gateway?.auth?.token ?? "");
    } else if (authMode === "password") {
      token = String(cfg?.gateway?.auth?.password ?? "");
    }

    if (!token) {
      token = String(process.env.OPENCLAW_GATEWAY_TOKEN ?? "");
    }

    if (!token) {
      if (debug) console.log("deepsafe debug: gateway auth token not found");
      return null;
    }

    const gatewayUrl = `http://localhost:${port}`;
    return { gatewayUrl, gatewayToken: token, port };
  } catch {
    return null;
  }
}

function checkGatewayAlive(gw: GatewaySettings, debug: boolean): boolean {
  try {
    const result = execFileSync("curl", [
      "-s", "-o", "/dev/null", "-w", "%{http_code}",
      "--max-time", "3",
      "-H", `Authorization: Bearer ${gw.gatewayToken}`,
      `${gw.gatewayUrl}/v1/chat/completions`,
    ], { encoding: "utf-8", timeout: 5000 });
    const code = parseInt(result.trim(), 10);
    if (debug) console.log(`deepsafe debug: gateway health check HTTP ${code}`);
    return code > 0 && code < 500;
  } catch {
    return false;
  }
}

function checkPythonAvailable(): { ok: boolean; message?: string } {
  const probe = spawnSync("python3", ["--version"], { encoding: "utf-8" });
  if (probe.error) {
    const code = String(probe.error?.code ?? "");
    if (code === "ENOENT") {
      return { ok: false, message: "python3 not found in PATH." };
    }
    return { ok: false, message: `failed to execute python3: ${String(probe.error.message ?? probe.error)}` };
  }
  if (probe.status !== 0) {
    return { ok: false, message: String(probe.stderr || probe.stdout || "python3 check failed") };
  }
  return { ok: true };
}

function runLegacyCheck(opts: any): never | void {
  const dimension = String(opts.dimension ?? "").toLowerCase().trim();
  if (dimension !== "persuasion") {
    console.error(
      `unsupported dimension: ${dimension}. currently supported: persuasion`,
    );
    process.exit(2);
  }

  const pyCheck = checkPythonAvailable();
  if (!pyCheck.ok) {
    console.error(`deepsafe error: ${pyCheck.message}`);
    process.exit(2);
  }

  const script = path.resolve(__dirname, "persuasion_probe.py");
  if (!fs.existsSync(script)) {
    console.error(`deepsafe error: persuasion probe not found: ${script}`);
    process.exit(2);
  }

  const pyArgs = [
    script,
    "--api-base",
    String(opts.apiBase),
    "--model",
    String(opts.model),
    "--api-key",
    String(opts.apiKey ?? "EMPTY"),
    "--mode",
    String(opts.mode ?? "fast"),
  ];
  if (opts.limit) pyArgs.push("--limit", String(opts.limit));
  if (opts.turns) pyArgs.push("--n-turns", String(opts.turns));
  if (opts.output) {
    pyArgs.push("--output", String(opts.output));
  }
  if (opts.debug) {
    console.log(`deepsafe debug: script=${script}`);
    console.log(`deepsafe debug: argv=${JSON.stringify(pyArgs)}`);
  }

  const run = spawnSync("python3", pyArgs, { stdio: "inherit" });
  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}

export default function register(api: CliApi) {
  api.registerCli(
    ({ program }) => {
      const cmd = program
        .command("deepsafe")
        .description("DeepSafe lightweight local checks");

      cmd
        .command("check")
        .description("Run DeepSafe check for one dimension")
        .requiredOption("--dimension <name>", "Risk dimension, e.g. persuasion")
        .requiredOption("--api-base <url>", "OpenAI-compatible API base")
        .requiredOption("--model <name>", "Model name")
        .option("--api-key <key>", "API key", "EMPTY")
        .option("--mode <mode>", "Run mode: fast|full", "fast")
        .option("--limit <n>", "Override topic count", "")
        .option("--turns <n>", "Override conversation turns", "")
        .option("--output <path>", "Output JSON path", "")
        .option("--debug", "Enable debug logs", false)
        .action((opts: any) => {
          runLegacyCheck(opts);
        });

      cmd
        .command("scan")
        .description("Run DeepSafe preflight scan")
        .option("--profile <mode>", "Scan profile: quick|full", "quick")
        .option("--ttl-days <n>", "Cache TTL in days", "3")
        .option("--force", "Force re-run and ignore cache", false)
        .option("--output <dir>", "Report output root directory", defaultOutputRoot())
        .option("--openclaw-config <path>", "OpenClaw config path", defaultOpenClawConfig())
        .option("--workspace <path>", "OpenClaw workspace path override", "")
        .option("--limit <n>", "Override model scan topic count", "")
        .option("--turns <n>", "Override model scan turns", "")
        .option("--skip-model", "Skip model scanner (probes)", false)
        .option("--debug", "Enable debug logs", false)
        .action((opts: any) => {
          const profile = String(opts.profile ?? "quick").toLowerCase();
          if (profile !== "quick" && profile !== "full") {
            console.error(`deepsafe error: invalid --profile ${String(opts.profile)}`);
            process.exit(2);
          }

          const pyCheck = checkPythonAvailable();
          if (!opts.skipModel && !pyCheck.ok) {
            console.error("");
            console.error("╔═══════════════════════════════════════════════════╗");
            console.error("║  ❌ python3 not found                              ║");
            console.error("╚═══════════════════════════════════════════════════╝");
            console.error("");
            console.error("  DeepSafe model security scan requires Python 3.");
            console.error("");
            console.error("  Install:");
            console.error("    macOS:   brew install python3  or  xcode-select --install");
            console.error("    Ubuntu:  sudo apt install python3");
            console.error("    Windows: https://www.python.org/downloads/");
            console.error("");
            console.error("  Re-run after installation. Or use --skip-model to skip model scan.");
            console.error("");
            process.exit(2);
          }

          const ttlNum = Number(opts.ttlDays ?? 3);
          if (!Number.isFinite(ttlNum) || ttlNum < 0) {
            console.error(`deepsafe error: invalid --ttl-days ${String(opts.ttlDays)}`);
            process.exit(2);
          }

          const openclawConfigPath = path.resolve(String(opts.openclawConfig || defaultOpenClawConfig()));
          const debug = Boolean(opts.debug);

          // ── Resolve gateway settings ──────────────────────────────────────
          ensureChatCompletionsEnabled(openclawConfigPath, debug);
          const gw = resolveGatewaySettings(openclawConfigPath, debug);

          let gatewayAlive = false;
          if (gw) {
            gatewayAlive = checkGatewayAlive(gw, debug);
            if (debug) {
              console.log(`deepsafe debug: gateway at ${gw.gatewayUrl} alive=${gatewayAlive}`);
            }
            if (!gatewayAlive) {
              console.log("  ⚠️  OpenClaw Gateway is not reachable. LLM-enhanced analysis and model probes will be disabled.");
              console.log("     Start your gateway with: openclaw gateway start");
              console.log("");
            }
          } else {
            console.log("  ⚠️  Could not resolve gateway settings from openclaw.json. LLM features disabled.");
            console.log("");
          }

          const canUseLlm = !!(gw && gatewayAlive);
          const runModel = !opts.skipModel && canUseLlm;

          if (!opts.skipModel && !canUseLlm) {
            console.log("  ℹ️  Model probes skipped (gateway not available). Static analysis will still run.");
            console.log("");
          }

          if (debug && gw) {
            console.log(
              `deepsafe debug: gateway=${gw.gatewayUrl} llm=${canUseLlm} model_probes=${runModel}`,
            );
          }

          const result = runScan({
            profile,
            ttlDays: Math.floor(ttlNum),
            force: Boolean(opts.force),
            outputRoot: path.resolve(String(opts.output || defaultOutputRoot())),
            openclawConfigPath,
            workspacePath: String(opts.workspace || ""),
            runModel,
            gatewayUrl: gw?.gatewayUrl || "",
            gatewayToken: gw?.gatewayToken || "",
            limit: String(opts.limit || ""),
            turns: String(opts.turns || ""),
            debug,
          });

          const s = result.report.scores;
          const totalFindings = result.report.findings.length;
          const critCount = result.report.findings.filter((f: any) => f.severity === "CRITICAL").length;
          const highCount = result.report.findings.filter((f: any) => f.severity === "HIGH").length;
          const medCount = result.report.findings.filter((f: any) => f.severity === "MEDIUM").length;
          const lowCount = result.report.findings.filter((f: any) => f.severity === "LOW").length;

          const riskIcon = s.total >= 85 ? "✅" : s.total >= 65 ? "⚠️" : s.total >= 40 ? "🔶" : "🚨";
          const riskLabel = s.total >= 85 ? "LOW RISK" : s.total >= 65 ? "MEDIUM RISK" : s.total >= 40 ? "HIGH RISK" : "CRITICAL";
          const durationSec = (result.report.metadata.durationMs / 1000).toFixed(1);

          const W = 52;
          const bar = "━".repeat(W);
          const padLine = (left: string, right: string) => {
            const vis = (s: string) => s.replace(/[\u{1F000}-\u{1FFFF}\u{2600}-\u{27BF}\u{FE00}-\u{FEFF}\u{1F900}-\u{1F9FF}]/gu, "XX");
            const pad = W - vis(left).length - vis(right).length;
            return left + " ".repeat(Math.max(1, pad)) + right;
          };

          console.log("");
          console.log(`  ┏${bar}┓`);
          console.log(`  ┃${" ".repeat(Math.floor((W - 26) / 2))}🛡️  DeepSafe Preflight Report${" ".repeat(Math.ceil((W - 26) / 2))}┃`);
          console.log(`  ┗${bar}┛`);
          console.log("");
          console.log(`  ${padLine(`  ${riskIcon}  Score: ${s.total}/100 (${riskLabel})`, `${totalFindings} findings`)}`);
          console.log(`  ${"─".repeat(W)}`);
          console.log(`  ${padLine("  🔴 CRITICAL  " + critCount, "🟠 HIGH  " + highCount)}`)
          console.log(`  ${padLine("  🟡 MEDIUM    " + medCount, "🟢 LOW   " + lowCount)}`)
          console.log(`  ${"─".repeat(W)}`);
          console.log(`  ${padLine("  🔒 Posture   " + s.posture + "/25", "🧩 Skill   " + s.skill + "/25")}`);
          console.log(`  ${padLine("  🧠 Model     " + s.model + "/25", "💾 Memory  " + s.memory + "/25")}`);
          console.log(`  ${"─".repeat(W)}`);
          console.log(`    ⏱️  ${durationSec}s  ·  ${result.cacheHit ? "📦 cached" : "🔄 fresh"}  ·  ${result.report.metadata.profile} mode`);
          console.log("");
          console.log(`    📄 ${result.paths.htmlPath}`);
          console.log("");

          if (result.exitCode === 2) {
            console.error("  ❌ Some modules failed — check the report for details.");
          }

          try {
            const htmlPath = result.paths.htmlPath;
            const platform = process.platform;
            if (platform === "darwin") {
              spawnSync("open", [htmlPath], { stdio: "ignore" });
            } else if (platform === "win32") {
              spawnSync("cmd", ["/c", "start", "", htmlPath], { stdio: "ignore" });
            } else {
              spawnSync("xdg-open", [htmlPath], { stdio: "ignore" });
            }
          } catch {
            // silently ignore if browser open fails
          }

          process.exit(result.exitCode);
        });

      cmd
        .command("report")
        .description("Show the latest DeepSafe report path")
        .option("--last", "Show latest report", true)
        .option("--output <dir>", "Report output root directory", defaultOutputRoot())
        .action((opts: any) => {
          const latest = loadLatest(path.resolve(String(opts.output || defaultOutputRoot())));
          if (!latest) {
            console.error("deepsafe error: no previous report found.");
            process.exit(2);
          }
          console.log("=== DeepSafe Latest Report ===");
          console.log(`generated_at: ${latest.generatedAt}`);
          console.log(`report_json: ${latest.jsonPath}`);
          console.log(`report_md: ${latest.mdPath}`);
        });
    },
    { commands: ["deepsafe"] },
  );
}
