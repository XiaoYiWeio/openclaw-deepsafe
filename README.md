<div align="center">
  <img src="assets/logo.png" alt="openclaw-deepsafe" width="200">
  <h1>openclaw-deepsafe</h1>
  <p><strong>Preflight Security Scanner for OpenClaw</strong></p>
  <p>One-command scan for deployment, skills, model safety, and memory risks — all locally.</p>
  <a href="https://github.com/XiaoYiWeio/DeepSafe"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-DeepSafe-blue?logo=github"></a>
</div>

---

## What It Does

**openclaw-deepsafe** scans your OpenClaw environment across 4 dimensions before you start working:

| Dimension | What it checks |
| :--- | :--- |
| **Deployment Posture** | Gateway exposure, authentication, proxy config, high-risk ports |
| **Skill / MCP** | Hidden characters, prompt injection, dangerous tool combos, excess permissions |
| **Model Safety** | Persuasion risk, sandbagging, deception tendency, hallucination detection |
| **Memory** | Plaintext secrets, persistent injection, PII exposure |

Results are cached for several days so you only scan when things change.

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

### Skip model scan

```bash
openclaw deepsafe scan --skip-model
```

### Show latest report

```bash
openclaw deepsafe report --last
```

## Output

Each scan produces:

- **HTML report** — auto-opens in browser, shareable on social media
- **JSON report** — machine-readable, for CI/CD integration
- **Markdown report** — human-readable summary

Reports are saved under `~/.openclaw/deepsafe/reports/<timestamp>/`.

## Model Safety Probes

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
