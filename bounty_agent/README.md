# SPAIDER Bounty Agent

An AI-assisted, **scope-enforced** bug bounty recon and triage agent. Authorized targets only.

> **Ethics gate:** Every command checks `scope.json` first. Targets not explicitly listed there are refused — the tool will not touch them. Nothing is ever exploited, brute-forced, or submitted to a bounty platform automatically. AI output is advisory; a human reviews and submits.

## What it does

| Stage | Tool | Safety constraint |
|---|---|---|
| Scope enforcement | `scope_gate` | Exact-host allowlist; refuses anything else |
| DNS check | `check_dns` | Public IPs only; private/loopback refused |
| Passive recon | `recon_subdomains` | crt.sh CT logs only — no intrusive traffic |
| HTTPS audit | `audit_https` | One request per host, 2s spacing, no redirects, no redirects, no fuzzing |
| AI triage | `triage` | AshnaAI classifies eligibility; human decides |
| Report drafting | `draft_report` | Drafts Markdown; **you** review and submit |

## What it will never do

- Exploit a vulnerability or verify one with attack payloads
- Fuzz, brute-force, or scan ports
- Accept a target outside `scope.json`
- Submit reports to HackerOne/Bugcrowd/Intigriti or email them to a program
- Work without explicit `authorized: true` in scope.json

## Setup

```bash
# 1. Clone and enter the repo, then:
python3 -m venv .venv && source .venv/bin/activate
pip install -r bounty_agent/requirements.txt

# 2. Create your real scope file (copy the example)
cp bounty_agent/scope.example.json bounty_agent/scope.json
# Edit it: list ONLY hosts a written bug bounty policy authorizes you to test,
# and set "authorized": true only if that is actually the case.

# 3. Set your AshnaAI key (get one at https://app.ashna.ai/account?tab=api)
export ASHNA_API_KEY="your-key-here"
# Optional: cheaper model for bulk triage
export ASHNA_MODEL="glm-5.3-flash"
```

## CLI usage

```bash
python3 -m bounty_agent.cli --scope bounty_agent/scope.json --audit --triage
```

Output: `bounty-report.json` with audits, AI triage, and draft report sections.

## MCP server usage (Claude Desktop, Cursor, Roo Code, VS Code Copilot)

```bash
python3 -m bounty_agent.mcp_server
```

Register in your client's MCP config:

```json
{
  "mcpServers": {
    "spaider-bounty": {
      "command": "python3",
      "args": ["-m", "bounty_agent.mcp_server"],
      "cwd": "/absolute/path/to/Muhammedsinanrp-Spaider-si",
      "env": {
        "ASHNA_API_KEY": "your-key",
        "SPAIDER_SCOPE_FILE": "bounty_agent/scope.json"
      }
    }
  }
}
```

Then in your AI client you can say things like: *"Check if example.com is in scope, run the HTTPS audit, and triage the findings."* The agent's tools refuse anything outside `scope.json`.

## AI model

Triage and drafting use the [AshnaAI API](https://www.ashna.ai/api-docs) — an OpenAI-compatible endpoint at `https://api.ashna.ai/v1/api`. Default model: `ashna-x1`; set `ASHNA_MODEL` to any catalog id (e.g. `glm-5.3-flash`) for cheaper bulk runs. Your API key stays in an environment variable and is never committed.

## Legal

Use only against assets you are **expressly and currently authorized** to test under a published bug bounty or engagement policy. Unauthorized testing is illegal in most jurisdictions. The findings produced (missing headers etc.) are informational observations, not confirmed vulnerabilities — most programs require demonstrated impact.
