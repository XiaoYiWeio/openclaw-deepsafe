# 🛡️ DeepSafe Preflight Security Report

> **Scanned at:** 2026-03-06T10:16:50.349Z  
> **Profile:** quick | **Duration:** 117.9s | **Plugin:** v0.1.0 | **Cache:** ❌ miss

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| **Overall Score** | [####------] **38/100** 🚨 CRITICAL RISK |
| **Score Breakdown** | Posture 5 + Skill 4 + Model 25 + Memory 4 = **38** |
| **Highest Severity** | 🔴 **CRITICAL** |
| **Total Findings** | **66** issue(s) |
| **Breakdown** | 🔴 2 Critical · 🟠 32 High · 🟡 26 Medium · 🟢 6 Low |

### Security Assessment

> Severe security posture with critical hardcoded credentials exposed over unencrypted HTTP and multiple command injection vulnerabilities in skills allowing arbitrary code execution.

**Critical Issues:**
- Hardcoded MiniMax API Key in config file — credential exposed via backups/version control
- Model API Key transmitted over HTTP to 35.220.164.252:3888 — actively intercepted in plaintext
- Hardcoded Feishu App Secret — enables account takeover if config leaked
- Command/argument injection in 15+ skill files — allows arbitrary system command execution
- Hardcoded Gateway Auth Token — exposes admin API to anyone with config access

**Recommended Actions:**
- 1. Move all API keys to environment variables or secrets manager immediately
- 2. Change MiniMax and Feishu API keys/secrets NOW — assume compromise
- 3. Switch provider endpoint from HTTP to HTTPS encrypting traffic
- 4. Audit and sanitize all skill files with exec/shell patterns — remove or restrict
- 5. Enable audit logging and configure agent sandboxing with tool restrictions

## 📋 Module Scores

| Module | Score | Risk | Findings | Time |
|--------|-------|------|----------|------|
| 🔒 Deployment & Config | **5**/25 | 🚨 CRITICAL RISK | 13 | 26.0s |
| 🧩 Skill / MCP | **4**/25 | 🚨 CRITICAL RISK | 23 | 26.4s |
| 🧠 Model Safety | **25**/25 | ⏭️ SKIP | — | — |
| 💾 Memory & History | **4**/25 | 🚨 CRITICAL RISK | 30 | 34.6s |

---

## 🔒 Deployment & Config

**Score:** [##--------] **21/100** — 🚨 CRITICAL RISK

### 🟡 API key for provider "zhangbo" is hardcoded in config

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Hardcoded API keys can be leaked through backups, version control, or log files — leading to unauthorized model usage and unexpected billing charges.

**Evidence:**

```
models.providers.zhangbo.apiKey = "sk-mtx*****************************************BR2N" (51 chars)
```

**Remediation:**

> Move the key to an environment variable (e.g. OPENCLAW_PROVIDER_KEY) and reference it in config, then rotate the exposed key.

### 🟠 Provider "zhangbo" uses unencrypted HTTP

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** API keys and model prompts are sent in plaintext — any network eavesdropper can intercept credentials and sensitive conversation data.

**Evidence:**

```
models.providers.zhangbo.baseUrl = "http://35.220.164.252:3888/v1"
API keys and model traffic are transmitted in plaintext over the network.
```

**Remediation:**

> Switch to HTTPS endpoint, or tunnel through SSH/VPN if the endpoint does not support TLS.

### 🟢 Enabled plugins have no explicit permission restrictions

> **Severity:** LOW — Monitor / Low priority

> ⚠️ **Risk:** A compromised or malicious plugin can access all tools and data without any boundary, potentially exfiltrating sensitive information or executing harmful actions.

**Evidence:**

```
2 plugin(s) enabled: openclaw-plugin-deepsafe, feishu
None define permissions, allowList, or denyList.
```

**Remediation:**

> Consider adding per-plugin permission constraints to limit the blast radius of a compromised plugin.

### 🟡 No logging or audit trail configured

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Without audit logging, you cannot detect, investigate, or prove security incidents — malicious actions will leave no trace.

**Evidence:**

```
No logging, audit, or log configuration section found in openclaw.json.
```

**Remediation:**

> Enable logging in openclaw.json to maintain an audit trail of agent actions. Consider setting logging.level to 'info' or higher.

### 🟡 No sandbox or tool restriction configured for agents

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Without sandboxing, agents can access your entire filesystem, network, and system commands — a single compromised agent could cause full system compromise.

**Evidence:**

```
No sandbox, isolation, or allowedTools configuration found.
Agents may have unrestricted access to system resources.
```

**Remediation:**

> Configure agent sandboxing (filesystem, network, command restrictions) in openclaw.json to limit agent capabilities.

### 🟢 Provider "zhangbo" uses a non-standard endpoint

> **Severity:** LOW — Monitor / Low priority

> ⚠️ **Risk:** Custom model endpoints may log your prompts and responses — your code, conversations, and sensitive data could be stored on unknown third-party servers.

**Evidence:**

```
models.providers.zhangbo.baseUrl = "http://35.220.164.252:3888/v1"
This endpoint is not a recognized major provider (OpenAI, Anthropic, Google, Azure).
```

**Remediation:**

> Verify you trust this endpoint's operator and their data handling policies. Review their privacy/security documentation.

### 🔴 Model API Key transmitted over HTTP

> **Severity:** CRITICAL — Must fix immediately

> ⚠️ **Risk:** The MiniMax API key is sent to http://35.220.164.252:3888 in cleartext, exposing credentials to network interception.

**Evidence:**

```
models.providers.zhangbo.baseUrl = "http://35.220.164.252:3888/v1"
```

**Remediation:**

> Change baseUrl to HTTPS (https://35.220.164.252:3888/v1) or use a local model provider with HTTPS.

### 🔴 Hardcoded MiniMax API Key

> **Severity:** CRITICAL — Must fix immediately

> ⚠️ **Risk:** API key is hardcoded in config file. If this file is version-controlled or shared, the key is compromised.

**Evidence:**

```
models.providers.zhangbo.apiKey = "sk-mtxeVbPPoxX5tTY8e67DzE2WlmtOPP4opgrvyv0bibfuBR2N"
```

**Remediation:**

> Use environment variable: set apiKey to ${MINIMAX_API_KEY} or load from secure vault.

### 🟠 Hardcoded Feishu App Secret

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Feishu app secret is hardcoded, allowing account takeover if config is exposed.

**Evidence:**

```
channels.feishu.appSecret = "SQCosy2itXH9MQUMPXe6sdt6HcOWVX7i"
```

**Remediation:**

> Load appSecret from environment variable (e.g., ${FEISHU_APP_SECRET}) or secrets manager.

### 🟠 Hardcoded Feishu Verification Token

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Webhook verification token is hardcoded, enabling attackers to forge events if compromised.

**Evidence:**

```
channels.feishu.verificationToken = "SaFV2nZEajlwNyKw87H0lb73MHasFpbI"
```

**Remediation:**

> Move to environment variable or secrets manager.

### 🟠 Hardcoded Gateway Auth Token

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Gateway authentication token is hardcoded in config, exposing the admin API.

**Evidence:**

```
gateway.auth.token = "c2bb17277256b651b6c9458222e1ee7ae0d313892a71f41d"
```

**Remediation:**

> Use environment variable (e.g., ${GATEWAY_TOKEN}) instead of hardcoding.

### 🟡 Gateway bind to loopback only

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Gateway binds to loopback (127.0.0.1), limiting remote administration but also preventing legitimate remote access if needed.

**Evidence:**

```
gateway.bind = "loopback"
```

**Remediation:**

> If remote access is needed, bind to specific IP with strong auth; otherwise this is acceptable.

### 🟢 Feishu group policy uses allowlist

> **Severity:** LOW — Monitor / Low priority

> ⚠️ **Risk:** Group access is restricted to allowlist (oc_zhangbo), which is good practice.

**Evidence:**

```
channels.feishu.groupPolicy = "allowlist", groupAllowFrom = ["oc_zhangbo"]
```

**Remediation:**

> No action needed - this is a secure configuration.

---

## 🧩 Skill / MCP

**Score:** [##--------] **15/100** — 🚨 CRITICAL RISK

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 3: description: Manage Apple Notes via the `memo` CLI on macOS (create, view, edit, delete, search, move, and export notes)...
  Line 10: Use `memo notes` to manage Apple Notes directly from the terminal. Create, view, edit, delete, search, move notes betwee...
  Line 13: - Install (Homebrew): `brew tap antoniorodr/memo && brew install antoniorodr/memo/memo`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 3: description: Manage Apple Reminders via the `remindctl` CLI on macOS (list, add, edit, complete, delete). Supports lists...
  Line 10: Use `remindctl` to manage Apple Reminders directly from the terminal. It supports list filtering, date-based views, and ...
  Line 13: - Install (Homebrew): `brew install steipete/tap/remindctl`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 338: | `cn-zh` | 中国 |
  Line 339: | `us-en` | 美国 |
  Line 340: | `uk-en` | 英国 |
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Skill "duckduckgo-search" grants broad shell execution permissions

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Wildcard shell access means the AI can run any command on your system — including destructive operations like rm -rf or data exfiltration.

**Evidence:**

```
allowed-tools declaration: Bash(duckduckgo-search:*), Bash(python:*), Bash(pip:*), Bash(uv:*)
High-risk entries: bash(python:*)
These allow the skill to execute arbitrary commands via shell.
```

**Remediation:**

> Restrict allowed-tools to specific commands instead of wildcards. For example, use Bash(pip:install) instead of Bash(pip:*).

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 3: description: "Fast file-name and content search using `fd` and `rg` (ripgrep)."
  Line 33: Fast file-name and content search using `fd` and `rg` (ripgrep).
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 3: description: "Interact with GitHub using the `gh` CLI. Use `gh issue`, `gh pr`, `gh run`, and `gh api` for issues, PRs, ...
  Line 8: Use the `gh` CLI to interact with GitHub. Always specify `--repo owner/repo` when not in a git directory, or use URLs di...
  Line 34: The `gh api` command is useful for accessing data not available through other subcommands.
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 11: Obsidian vault = folder with Markdown files + `.obsidian/` config.
  Line 15: - **Vault Path:** `/home/ruslan/webdav/data/ruslain`
  Line 16: - **Env:** `OBSIDIAN_VAULT=/home/ruslan/webdav/data/ruslain`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟡 Dangerous execution primitive in skill file

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** This skill contains code that can execute arbitrary system commands — a compromised or malicious skill could delete files, install malware, or steal credentials.

**Evidence:**

```
Matched patterns:
  Line 14: import subprocess
  Line 81: result = subprocess.run(
  Line 87: except (FileNotFoundError, subprocess.TimeoutExpired):
These functions can execute arbitrary system commands.
```

**Remediation:**

> Validate and sanitize all inputs before passing to execution functions. Consider using a sandbox or allow-list for permitted commands.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 7: - **Project Renamed** — `web-scraper` → `playwright-scraper-skill`
  Line 37: - ✅ `playwright-simple.js` — Fast simple scraper
  Line 38: - ✅ `playwright-stealth.js` — Anti-bot protected version (primary) ⭐
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 20: 1. Create an Issue with `[Feature Request]` in the title
  Line 73: - `Add: new feature`
  Line 74: - `Fix: issue description`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 78: **Error message:** `Error: Cannot find module 'playwright'`
  Line 88: **Error message:** `browserType.launch: Executable doesn't exist`
  Line 97: **Error message:** `Permission denied`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 72: - Hide `navigator.webdriver`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 70: - 隱藏 `navigator.webdriver`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 19: | **Dynamic Sites** | Medium | Playwright Simple | `scripts/playwright-simple.js` |
  Line 20: | **Cloudflare Protected** | High | **Playwright Stealth** ⭐ | `scripts/playwright-stealth.js` |
  Line 40: Use OpenClaw's built-in `web_fetch` tool:
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟡 Dangerous execution primitive in skill file

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** This skill contains code that can execute arbitrary system commands — a compromised or malicious skill could delete files, install malware, or steal credentials.

**Evidence:**

```
Matched patterns:
  Line 130: const { spawn } = require('child_process');
These functions can execute arbitrary system commands.
```

**Remediation:**

> Validate and sanitize all inputs before passing to execution functions. Consider using a sandbox or allow-list for permitted commands.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 118: for url in "${URLS[@]}"; do
  Line 120: node scripts/playwright-stealth.js "$url" > "output_$(date +%s).json"
  Line 156: reject(new Error(`Exit code: ${code}`));
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 4: SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  Line 5: SKILL_DIR="$(dirname "$SCRIPT_DIR")"
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 31: console.log(`📱 導航到: ${url}`);
  Line 34: console.log(`⏳ 等待 ${waitTime}ms...`);
  Line 50: console.log(`📸 截圖已儲存: ${screenshotPath}`);
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 25: const screenshotPath = process.env.SCREENSHOT_PATH || `./screenshot-${Date.now()}.png`;
  Line 40: console.log(`🔒 反爬模式: ${headless ? '無頭' : '有頭'}`);
  Line 82: console.log(`📱 導航到: ${url}`);
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟠 Command/argument injection pattern detected

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Shell expansion or command chaining in skill content can allow arbitrary code execution when the AI processes tool arguments.

**Evidence:**

```
Injection patterns found:
  Line 23: - OpenAI: `OPENAI_API_KEY`
  Line 24: - Anthropic: `ANTHROPIC_API_KEY`
  Line 25: - xAI: `XAI_API_KEY`
Patterns like ${...}, `...`, $(...), or pipe-to-shell can inject arbitrary commands.
```

**Remediation:**

> Remove shell expansion syntax. Use explicit, sanitized parameters instead of dynamic command construction.

### 🟢 apple-notes delete operation - interactive but destructive

> **Severity:** LOW — Monitor / Low priority

> ⚠️ **Risk:** The memo CLI supports deleting notes (`memo notes -d`) which is a destructive operation, though it requires interactive selection by default.

**Evidence:**

```
- Delete a note: `memo notes -d`
  - Interactive selection of note to delete.
```

**Remediation:**

> This is acceptable as delete requires interactive user confirmation. Consider documenting that automation scripts should use caution when piping input to this command.

### 🟢 apple-reminders delete operations - destructive but require IDs

> **Severity:** LOW — Monitor / Low priority

> ⚠️ **Risk:** The remindctl CLI supports deleting reminders and lists (`remindctl delete`, `remindctl list --delete`) which are destructive, though they require specific IDs.

**Evidence:**

```
- Delete by id: `remindctl delete 4A83 --force`
- Delete list: `remindctl list Work --delete`
```

**Remediation:**

> Acceptable as operations require explicit IDs. The --force flag is noted which is appropriate for automation scenarios.

### 🟢 apple-reminders list delete - destructive account-level operation

> **Severity:** LOW — Monitor / Low priority

> ⚠️ **Risk:** Deleting a reminder list (`--delete`) permanently removes all reminders within that list - a batch destructive action.

**Evidence:**

```
- Delete list: `remindctl list Work --delete`
```

**Remediation:**

> Consider adding a warning about batch deletion implications or requiring confirmation for list deletion.

---

## 🧠 Model Safety

**Status:** ⏭️ SKIPPED
Reason: Skipped (--skip-model or gateway not available)

---

## 💾 Memory & History

**Score:** [##--------] **17/100** — 🚨 CRITICAL RISK

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 21: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟠 Plaintext secret found: OpenAI-style API key (sk-...)

> **Severity:** HIGH — Fix within 24 hours

> ⚠️ **Risk:** Credentials stored in plaintext can be extracted by any process with file access — leading to account takeover, unauthorized API usage, and financial loss.

**Evidence:**

```
Line 2246: sk-m*******************************************BR2N
Pattern: OpenAI-style API key (sk-...)
```

**Remediation:**

> Remove the secret from this file, rotate the compromised credential, and use environment variables or a secret manager instead.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: US phone number pattern
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

### 🟡 Personally identifiable information (PII) in session data

> **Severity:** MEDIUM — Fix in next iteration

> ⚠️ **Risk:** Stored PII increases your exposure in a data breach and may violate privacy regulations (GDPR, CCPA). Personal data could also be inadvertently sent to third-party model providers.

**Evidence:**

```
Detected PII types: IP address (potential internal host)
PII stored in session history may violate data protection regulations and increases breach impact.
```

**Remediation:**

> Redact or anonymize PII in stored sessions. Consider enabling auto-redaction for future memory writes.

---

_Powered by [openclaw-deepsafe](https://github.com/XiaoYiWeio/openclaw-deepsafe) — Preflight Security Scanner for OpenClaw_

> ⭐ If this report helped you, consider giving us a star on [GitHub](https://github.com/XiaoYiWeio/openclaw-deepsafe)!
