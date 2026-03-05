<div align="center">
  <img src="assets/logo.png" alt="openclaw-deepsafe" width="200">
  <h1>openclaw-deepsafe</h1>
  <p><strong>Preflight Security Scanner for OpenClaw</strong></p>
  <p>One-command scan &mdash; 28+ secret patterns, 15+ skill analyzers, 4 model safety benchmarks, LLM-enhanced semantic analysis. Fully local.</p>
  <a href="https://github.com/XiaoYiWeio/DeepSafe"><img alt="GitHub" src="https://img.shields.io/badge/Powered_by-DeepSafe-blue?logo=github"></a>
</div>

---

## What It Does

**openclaw-deepsafe** is a preflight security scanner that gives you a full risk assessment before you start working with OpenClaw. It's **not** a runtime interceptor — it scans once, caches results, and lets you focus on your work.

### Scan Dimensions

| Dimension | Checks | Approach |
| :--- | :--- | :--- |
| **Deployment Posture** | Gateway exposure, auth, TLS, MCP supply chain, sandbox, logging, provider trust | 10+ rules + LLM config analysis |
| **Skill / MCP** | Prompt injection, hidden chars, encoded payloads, embedded secrets, data exfiltration, destructive ops, argument injection, auto-execute bypass | 15+ static analyzers + LLM semantic audit |
| **Model Safety** | Persuasion manipulation, capability concealment (sandbagging), deception tendency, hallucination detection | 4 benchmarks via DeepSafe framework |
| **Memory & History** | Plaintext secrets, PII, injection persistence, email ops, destructive actions, privilege escalation traces | 28+ secret patterns, 9 PII detectors + LLM behavior analysis |

### Key Differentiators

- **Model safety evaluation** — the only OpenClaw plugin that benchmarks your model for persuasion, deception, sandbagging, and hallucination risks
- **LLM-enhanced semantic analysis** — goes beyond regex; uses your configured model to understand context and detect subtle risks
- **Hybrid detection** — fast rule-based first pass + deep LLM analysis for robustness
- **Preflight, not runtime** — scan once, get a risk portrait, no performance impact on daily use

## Install

```bash
openclaw plugins install github:XiaoYiWeio/openclaw-deepsafe
```

Then restart OpenClaw Gateway.

## Usage

### Quick scan (recommended)

```bash
openclaw deepsafe scan
```

The plugin reads model configuration directly from `~/.openclaw/openclaw.json` — no extra flags needed.

### Full scan

```bash
openclaw deepsafe scan --profile full
```

### Skip model scan (faster)

```bash
openclaw deepsafe scan --skip-model
```

### Show latest report

```bash
openclaw deepsafe report --last
```

## Output

Each scan produces:

- **HTML report** — auto-opens in browser, social-media-ready with risk warnings per finding
- **JSON report** — machine-readable, for CI/CD integration
- **Markdown report** — human-readable summary

Reports are saved under `~/.openclaw/deepsafe/reports/<timestamp>/`.

## Detection Coverage

### Secret Patterns (28+)

OpenAI, Anthropic, Hugging Face, GitHub (PAT/OAuth/App/fine-grained), GitLab, Slack (bot/user/session/webhook), AWS (access/temporary), Google Cloud, Azure, Stripe, SendGrid, Twilio, PEM/SSH private keys, Database URLs, JWT, HTTP Basic Auth, and generic high-entropy secrets.

### Skill & MCP Analyzers (15+)

Hidden Unicode, prompt injection, dangerous runtimes, base64/hex encoded payloads, sensitive file references, embedded credentials, system prompt extraction, argument injection, data exfiltration chains, destructive actions on resources, auto-execute without confirmation, high-risk service tools (email/messaging), permission analysis, source trust verification, plus LLM semantic audit.

### Model Safety Probes (4)

| Probe | What it measures |
| :--- | :--- |
| **Persuasion** | Can the model manipulate opinions in multi-turn dialogue? |
| **Sandbagging** | Does the model strategically hide its capabilities? |
| **Deception** | Does the model's reasoning contradict its actions? |
| **HaluEval** | Can the model detect hallucinated information? |

## Requirements

- **Python 3** — required for model safety probes (standard library only, no pip install needed)
- **OpenClaw** — with a configured model in `~/.openclaw/openclaw.json`

## Debug

```bash
openclaw deepsafe scan --debug --force
```

- `--debug` prints detailed logs and saves stdout/stderr for each probe
- `--force` bypasses the scan cache

## Powered by

<a href="https://github.com/XiaoYiWeio/DeepSafe">
  <img src="assets/deepsafe-logo-dark.svg" alt="DeepSafe" width="160">
</a>

Part of the [DeepSafe](https://github.com/XiaoYiWeio/DeepSafe) AI Safety Evaluation Framework.
