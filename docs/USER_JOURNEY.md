# Vigil SOC — End-to-End User Journey

> A complete walkthrough from first login to autonomous 24/7 operations.

---

## Table of Contents

1. [Overview](#overview)
2. [Phase 0 — First Boot](#phase-0--first-boot)
3. [Phase 1 — Onboarding Wizard](#phase-1--onboarding-wizard)
4. [Phase 2 — Connect Your Stack](#phase-2--connect-your-stack)
5. [Phase 3 — Alerts Arrive](#phase-3--alerts-arrive)
6. [Phase 4 — AI Triage](#phase-4--ai-triage)
7. [Phase 5 — Deep Investigation](#phase-5--deep-investigation)
8. [Phase 6 — Threat Hunting](#phase-6--threat-hunting)
9. [Phase 7 — Response & Containment](#phase-7--response--containment)
10. [Phase 8 — Case Management](#phase-8--case-management)
11. [Phase 9 — Reporting](#phase-9--reporting)
12. [Phase 10 — Autonomous Mode (Daemon)](#phase-10--autonomous-mode-daemon)
13. [Vigil Assistant — Conversational SOC](#vigil-assistant--conversational-soc)
14. [AI Provider Routing](#ai-provider-routing)
15. [Agent Capabilities Quick Reference](#agent-capabilities-quick-reference)
16. [Daily Analyst Routine](#daily-analyst-routine)

---

## Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         VIGIL SOC PLATFORM                              │
│                                                                         │
│   Alerts ──► AI Triage ──► Investigation ──► Response ──► Case ──► Report │
│                │                                                        │
│                └──► 13 Specialized Agents                               │
│                └──► 30+ Security Integrations                           │
│                └──► Works with Claude, OpenAI, Ollama                   │
└─────────────────────────────────────────────────────────────────────────┘
```

**Who this is for:** SOC analysts, incident responders, and security engineers deploying an AI-native SOC platform for the first time or daily operations.

**What Vigil does:**
- Ingests alerts from your SIEM/EDR
- Triages them with specialized AI agents
- Investigates, hunts, responds — with human approval at key decision points
- Tracks every action in cases with full audit trail
- Generates board-ready reports
- Runs autonomously 24/7 when you need it to

---

## Phase 0 — First Boot

### Start the Stack

```bash
git clone --recurse-submodules https://github.com/Vigil-SOC/vigil.git
cd vigil
./start.sh
```

What happens under the hood:

```
./start.sh
  │
  ├── docker compose up -d postgres redis     # infrastructure
  ├── source venv/bin/activate
  ├── pip install -r requirements.txt         # Python deps + submodules
  ├── uvicorn backend.main:app --port 6987    # FastAPI backend
  └── cd frontend && npm run dev              # React UI on port 6988
```

**Backend startup sequence (backend/main.py):**

```
1. SecretsManager initializes (~/.vigil/secrets.enc)
2. restore_all_integration_secrets()   ← loads saved API keys into os.environ
3. PostgreSQL connection pool opens
4. MCP client connects to configured servers (SentinelOne, Splunk, etc.)
5. Workflow registry loads from workflows/
6. Daemon scheduler starts (if --daemon flag)
7. FastAPI routers registered → API ready
```

> The `restore_all_integration_secrets()` step is critical: it re-hydrates
> `os.environ` from the encrypted secrets store so MCP subprocesses inherit
> the correct API tokens after every container restart.

**Open the UI:** `http://localhost:6988`

---

## Phase 1 — Onboarding Wizard

On first login you land on the **Onboarding Wizard** — a guided setup flow.

```
┌──────────────────────────────────────────────────────┐
│  Step 1   Choose your AI provider                    │
│  Step 2   Add your first LLM key                     │
│  Step 3   Connect a security integration             │
│  Step 4   Run a test query                           │
│  Step 5   You're ready ✓                             │
└──────────────────────────────────────────────────────┘
```

### Step 1 — Choose AI Provider

Navigate to **Settings → AI / LLM Providers → Add Provider**.

| Provider | Model | Best For |
|----------|-------|----------|
| Anthropic (Claude) | claude-sonnet-4-6 | Full capabilities, extended thinking |
| OpenAI | gpt-4o | OpenAI ecosystem, familiar API |
| Ollama | llama3.1, qwen2.5 | Air-gapped / on-premises deployments |

> All providers get identical MCP tool access. Switching providers doesn't
> lose any integrations.

### Step 2 — Add API Key

Enter your key in the UI form. It flows:

```
UI form → set_secret(env_var, value)
              │
              ├──► ~/.vigil/secrets.enc   (encrypted, persists restarts)
              └──► os.environ              (in-process, for MCP subprocesses)
```

No keys are stored in the database or committed to source code.

### Default Login (DEV_MODE)

| Field | Value |
|-------|-------|
| URL | http://localhost:6988 |
| Username | admin |
| Password | admin123 |

> `DEV_MODE=true` (default) bypasses authentication entirely for local
> development. Set it to `false` in `.env` to enable JWT auth for shared
> deployments.

---

## Phase 2 — Connect Your Stack

Navigate to **Settings → Integrations**.

### Supported Integrations (30+)

| Category | Examples |
|----------|---------|
| **EDR / Endpoint** | SentinelOne, CrowdStrike Falcon, Microsoft Defender, Carbon Black |
| **SIEM / Log** | Splunk, Elastic SIEM, Azure Sentinel, QRadar, Sumo Logic |
| **Threat Intel** | VirusTotal, Shodan, AlienVault OTX, MISP |
| **Cloud Security** | AWS Security Hub, AWS GuardDuty, Wiz, Prisma Cloud |
| **Ticketing** | Jira, ServiceNow, PagerDuty |
| **Communication** | Slack, Microsoft Teams, PagerDuty |
| **Forensics** | Timesketch, Velociraptor, CAPE Sandbox |

### SentinelOne Example

1. Settings → Integrations → SentinelOne → Configure
2. Enter: Console URL, API Token
3. Save → credentials go to encrypted store
4. Backend auto-connects the `purple-mcp` MCP server

**What you get:** 33 live tools available to every AI agent:

```
sentinelone_list_alerts          sentinelone_threat_intel_by_ip
sentinelone_search_alerts        sentinelone_threat_intel_by_hash
sentinelone_get_alert            sentinelone_threat_intel_by_domain
sentinelone_list_vulnerabilities sentinelone_cve_search_by_id
sentinelone_powerquery           sentinelone_purple_ai
... and 23 more
```

### What Happens at Connection Time

```
Settings save
  │
  ├── split_secrets() routes api_token → secrets store
  ├── set_secret("SENTINELONE_API_TOKEN", value)
  │     ├── writes ~/.vigil/secrets.enc
  │     └── sets os.environ["SENTINELONE_API_TOKEN"]
  │
  └── MCP client: connect_to_server("sentinelone")
        │
        ├── reads mcp-config.json entry
        ├── substitutes ${SENTINELONE_API_TOKEN} from os.environ
        ├── spawns: uvx purple-mcp --mode stdio
        └── caches 33 tools in tools_cache → MCPRegistry
```

---

## Phase 3 — Alerts Arrive

Alerts enter Vigil through three paths:

### Path A — Daemon Polling (Autonomous)

```
daemon/poller.py
  │
  ├── polls SentinelOne every N seconds: sentinelone_list_alerts
  ├── polls Splunk: saved search results
  ├── polls CrowdStrike: detections API
  └── writes raw alerts → findings table (PostgreSQL)
```

### Path B — Manual Finding Creation

Dashboard → Findings → New Finding → fill form → Save

### Path C — API Ingestion

```bash
curl -X POST http://localhost:6987/api/findings \
  -H "Content-Type: application/json" \
  -d '{"title": "Suspicious PowerShell", "severity": "high", ...}'
```

### Findings in the UI

**Dashboard → Findings** shows all alerts with:

| Column | Description |
|--------|-------------|
| Severity | Critical / High / Medium / Low |
| Status | New / Triaged / In Progress / Resolved |
| Source | SentinelOne / Splunk / Manual / API |
| MITRE | ATT&CK technique tags (auto-populated after triage) |
| Agent | Which AI agent last touched it |

---

## Phase 4 — AI Triage

### Trigger Triage

Click any finding → **Run Agent** → Select **Triage Agent** → Run

Or: select multiple findings → **Bulk Triage**

### What Triage Agent Does

```
Triage Agent (fast, no extended thinking)
  │
  ├── Reads finding details
  ├── Queries: sentinelone_get_alert (get full context)
  ├── Queries: sentinelone_threat_intel_by_ip (enrich IOCs)
  ├── Applies 7,200+ detection rules for context
  │
  └── Returns:
        - Severity assessment (Critical/High/Medium/Low/False Positive)
        - Confidence score (0.0 – 1.0)
        - MITRE ATT&CK technique(s)
        - Recommended next step (Investigate / Monitor / Close)
        - Triage summary (3–5 sentences)
```

### Confidence & Auto-Approval

| Confidence | Action |
|------------|--------|
| ≥ 0.90 | Auto-approve triage, proceed to investigation |
| 0.85–0.89 | Auto-approve + flag for review |
| 0.70–0.84 | Queue for human approval |
| < 0.70 | Monitor only |

Approval queue: **Dashboard → Approval Queue**

### Triage Result Example

```
Finding: Suspicious PowerShell Execution — DESKTOP-ABC123
Severity: HIGH (confidence: 0.89)

MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell)

Assessment: The base64-encoded PowerShell command downloads and executes
a payload from an external IP (185.220.x.x, Tor exit node per threat
intel). Pattern matches known Cobalt Strike stager behavior.

Recommended: ESCALATE → Investigator Agent for deep-dive analysis
```

---

## Phase 5 — Deep Investigation

### Trigger Investigation

From a triaged finding → **Run Agent** → **Investigator Agent** → Run

Or from Vigil Assistant: *"Investigate finding #1234"*

### What Investigator Agent Does (with extended thinking)

```
Investigator Agent (thorough, extended thinking enabled)
  │
  Round 1: sentinelone_get_alert → full alert JSON
  Round 2: sentinelone_search_alerts → related alerts same host
  Round 3: sentinelone_threat_intel_by_ip → IOC enrichment
  Round 4: sentinelone_powerquery → historical activity
  Round 5: sentinelone_get_alert_investigation_report → SentinelOne AI report
  Round 6: synthesize → final investigation report
  │
  └── Returns:
        - Root cause analysis
        - Full attack timeline
        - Affected assets (hosts, users, IPs)
        - Evidence collected
        - MITRE ATT&CK chain
        - Recommended containment steps
```

### Multi-Agent Investigation Workflow

For complex incidents, trigger the **Full Investigation** workflow:

```
Full Investigation Workflow
  │
  Phase 1: Investigator Agent      — root cause + evidence
  Phase 2: MITRE Analyst Agent     — ATT&CK mapping + technique details
  Phase 3: Correlator Agent        — find related alerts, build attack chain
  Phase 4: Responder Agent         — containment recommendations
  Phase 5: Reporter Agent          — final investigation report
```

Launch from: **Workflows** page → Full Investigation → Select finding → Execute

---

## Phase 6 — Threat Hunting

### Trigger a Threat Hunt

Vigil Assistant: *"Hunt for signs of lateral movement in the last 7 days"*

Or: **Workflows** → Threat Hunt → Configure hypothesis → Execute

### Threat Hunt Workflow

```
Threat Hunt Workflow
  │
  Phase 1: Threat Hunter Agent
  │   ├── sentinelone_powerquery: hunt for living-off-the-land binaries
  │   ├── sentinelone_search_alerts: anomalous authentication patterns
  │   └── Hypothesis: "Attacker may be using PsExec for lateral movement"
  │
  Phase 2: Network Analyst Agent
  │   ├── Query unusual outbound connections
  │   ├── Correlate C2 beaconing patterns
  │   └── Flag suspicious IP ranges
  │
  Phase 3: Malware Analyst Agent
  │   ├── sentinelone_threat_intel_by_hash: check file hashes
  │   └── Behavioral analysis of suspicious processes
  │
  Phase 4: Threat Intel Agent
  │   ├── sentinelone_threat_intel_by_ip: IOC enrichment
  │   ├── sentinelone_threat_intel_by_domain: domain reputation
  │   └── Cross-reference threat actor TTPs
  │
  Phase 5: Reporter Agent
      └── Hunting report with IOCs, TTPs, and new detection opportunities
```

### Detection Engineering from Hunt Findings

After a hunt: Vigil Assistant → *"Create a detection rule for the PsExec lateral movement pattern we found"*

The Detection Engineering agent uses 7,200+ existing rules as templates to generate:
- Sigma rule
- Splunk ESCU search
- Elastic KQL query

---

## Phase 7 — Response & Containment

### Recommended Actions

After investigation, the Responder Agent outputs:

```
Containment Recommendations:
  1. [CRITICAL] Isolate host DESKTOP-ABC123 from network
  2. [HIGH]     Block IP 185.220.x.x at perimeter firewall
  3. [MEDIUM]   Reset credentials for user john.doe@company.com
  4. [LOW]      Run full AV scan on affected hosts
```

### Approval Workflow

High-impact actions require approval before execution:

```
Responder Agent recommends: isolate_host(DESKTOP-ABC123)
  │
  └── confidence: 0.87  →  REQUIRES APPROVAL
        │
        ▼
  Approval Queue (Dashboard → Approval Queue)
        │
        ├── Analyst reviews: action, blast radius, evidence
        ├── APPROVE  →  action executes via MCP tool
        └── REJECT   →  logged, alternative proposed
```

**Force Manual Approval** — enable via Dashboard checkbox to require human
approval for ALL actions regardless of confidence. Use during:
- First weeks of deployment
- Active high-severity incidents
- Compliance-mandated environments

### Automated Containment Actions

When approved (or in autonomous mode with high confidence):

| Action | MCP Tool Used |
|--------|--------------|
| Isolate host | `sentinelone` → isolate endpoint API |
| Block IP | Firewall integration |
| Kill process | EDR response API |
| Quarantine file | EDR response API |
| Disable user account | Identity provider integration |

---

## Phase 8 — Case Management

Every finding can be promoted to a **Case** for full incident lifecycle tracking.

### Create a Case

Finding detail page → **Promote to Case** → Fill in:
- Title, Severity, Priority
- Assignee
- Related findings (auto-linked)

### Case Tabs

| Tab | What's Here |
|-----|------------|
| **Overview** | Status, priority, assignee, SLA timer, timeline |
| **Findings** | All security findings linked to this incident |
| **Activities** | Full audit trail — every agent action, human action, approval |
| **Resolution** | Step-by-step resolution documentation |

### Case Status Flow

```
New  ──►  In Progress  ──►  Resolved  ──►  Closed
          │
          └── SLA timer running (configurable per severity)
```

### Resolution Documentation

Each step records:
- **Description** — what was done
- **Action Taken** — detailed explanation
- **Result** — outcome / verification
- **Timestamp** — auto-recorded

### MITRE ATT&CK Layer

From a case: **Generate ATT&CK Layer** → visual heatmap of all techniques
involved in the incident, exportable to MITRE ATT&CK Navigator.

---

## Phase 9 — Reporting

### PDF Case Report

Case detail → **Generate Report** → PDF with:
- Executive summary
- Full finding timeline
- Evidence collected
- Resolution steps
- MITRE ATT&CK mapping
- Analyst notes

### Board Brief

Vigil Assistant: *"Generate board brief"*

One-page executive report (non-technical language):

| Section | Contents |
|---------|----------|
| Risk Posture | Red/Yellow/Green indicator + one-line summary |
| Key Metrics | Kill chains validated, detection coverage %, MTTR, open criticals |
| Top 3 Actions | Risk description + fix type (budget/policy/technical) + impact |
| 30/60/90 Trend | Exposure count direction — improving, stable, or degrading |

> No CVE numbers or ATT&CK IDs in the board brief. Pure business language.

### Threat Hunt Report

Auto-generated at end of every hunt workflow:
- Hypothesis tested
- Evidence found / not found
- New IOCs discovered
- Recommended new detections
- Hunter's notes

---

## Phase 10 — Autonomous Mode (Daemon)

### Start Daemon

```bash
./start.sh --daemon
```

Or: Dashboard → Daemon Status → Enable

### What the Daemon Does 24/7

```
daemon/orchestrator.py
  │
  ├── daemon/poller.py        polls SentinelOne, Splunk, etc. for new alerts
  │
  ├── daemon/processor.py     for each new alert:
  │     ├── Triage Agent      rapid severity scoring
  │     ├── if Critical:      escalate to Investigator Agent
  │     └── write findings    save results to PostgreSQL
  │
  ├── daemon/responder.py     if confidence ≥ threshold AND auto_response:
  │     ├── execute containment actions
  │     └── log to approval queue (even if auto-approved)
  │
  └── daemon/scheduler.py     scheduled tasks:
        ├── daily threat hunt (2 AM)
        ├── weekly compliance check
        └── nightly detection coverage audit
```

### Cost Guardrails

```
ORCHESTRATOR_MAX_COST=10.00          # max $ per day
ORCHESTRATOR_MAX_HOURLY_COST=2.00    # max $ per hour
DAEMON_CONFIDENCE_THRESHOLD=0.85     # min confidence for auto-action
```

When cost limits are hit, the daemon pauses and notifies via Slack/email.

### Daemon Configuration

```env
DAEMON_AUTO_TRIAGE=true              # auto-triage all new alerts
DAEMON_AUTO_RESPOND=false            # set true for autonomous containment
DAEMON_CONFIDENCE_THRESHOLD=0.85     # min confidence for auto-actions
ORCHESTRATOR_MAX_COST=10.00          # daily cost ceiling
```

---

## Vigil Assistant — Conversational SOC

The **Vigil Assistant** chat panel is how analysts interact naturally with
the entire platform. It's powered by your active AI provider and has full
access to all connected security tools.

### Example Conversations

```
You: List recent SentinelOne alerts from the last 24 hours
Vigil: [calls sentinelone_list_alerts] Here are 7 alerts from the last 24h:
       1. Suspicious PowerShell — DESKTOP-ABC (HIGH, 2h ago)
       2. Lateral Movement via PsExec — SERVER-01 (CRITICAL, 4h ago)
       ...

You: Investigate alert #2 — the lateral movement on SERVER-01
Vigil: [calls sentinelone_get_alert, sentinelone_search_alerts,
        sentinelone_threat_intel_by_ip]
       Root cause: Attacker gained initial access via phishing email...

You: What's the MITRE technique for this?
Vigil: T1021.002 (Remote Services: SMB/Windows Admin Shares)
       Also observed: T1078 (Valid Accounts), T1550.002 (Pass the Hash)

You: Generate a board brief for last month's incidents
Vigil: [queries findings and cases] Generating board brief...
       Risk Posture: YELLOW — 3 confirmed intrusion attempts, all contained...

You: Hunt for any other hosts that may be compromised by the same actor
Vigil: [calls sentinelone_powerquery, sentinelone_search_alerts]
       Found 2 additional hosts with similar IOCs: WS-042, WS-089...
```

### Available via Chat

| Capability | Example Prompt |
|------------|---------------|
| Live alert query | *"List critical alerts from today"* |
| Threat intel lookup | *"Is 45.33.32.156 malicious?"* |
| IOC enrichment | *"Look up hash abc123..."* |
| Investigation | *"Investigate finding #456"* |
| Threat hunting | *"Hunt for signs of ransomware staging"* |
| Case summary | *"Summarize case #789"* |
| Report generation | *"Generate board brief"* |
| Detection rules | *"Write a Sigma rule for this behavior"* |
| MITRE mapping | *"Map these TTPs to ATT&CK"* |
| Compliance | *"Check our NIST CSF coverage"* |

### Using Specialized Agents via Chat

Prefix your prompt or select from the agent picker:

```
[Investigator] Perform deep-dive on the lateral movement incident
[Threat Hunter] Hunt for living-off-the-land binaries across all endpoints
[Malware Analyst] Analyze this file hash: d41d8cd98f00b204e9800998ecf8427e
[MITRE Analyst] Map these behaviors to ATT&CK techniques
[Reporter] Generate executive summary of this week's incidents
```

---

## AI Provider Routing

Vigil automatically selects the right code path based on your active provider:

```
User message → POST /api/claude/chat/stream
                     │
                     ▼
              resolve active_provider
                     │
              ┌──────┴──────────┐
              ▼                 ▼
         Anthropic?        OpenAI / Ollama
         ClaudeService     LLMRouter + Bifrost
         (Anthropic SDK)   (OpenAI-compatible)
              │                 │
              └────────┬────────┘
                       ▼
              MCP Tools Available (all providers)
                       │
                 ┌─────┴─────┐
                 ▼           ▼
           tool_calls?    Text response
           Agentic loop   Stream to UI
           (up to 6 rounds)
```

### What Changes Per Provider

| Aspect | Anthropic | OpenAI / Ollama |
|--------|-----------|-----------------|
| Tool format | `input_schema` | `parameters` |
| Agentic loop | ClaudeService built-in | New loop in `claude.py` |
| Streaming with tools | Streamed | Batch then emit |
| Extended thinking | Yes (Investigator) | No |
| Max context | 200K tokens | Model-dependent |

### Tool Compatibility by Ollama Model

| Model | Function Calling | MCP Tools |
|-------|-----------------|-----------|
| llama3.1 | ✅ | ✅ |
| llama3.2 | ✅ | ✅ |
| qwen2.5 | ✅ | ✅ |
| mistral-nemo | ✅ | ✅ |
| deepseek-r1 | ✅ | ✅ |
| llama2 | ❌ | ❌ (text only) |
| codellama | ❌ | ❌ (text only) |

---

## Agent Capabilities Quick Reference

| Agent | Thinking | Speed | When to Use |
|-------|----------|-------|-------------|
| **Triage** | No | Fast | Prioritize alert queue, first assessment |
| **Investigator** | Yes | Thorough | Deep-dive root cause, full evidence |
| **Threat Hunter** | Yes | Balanced | Proactive hypothesis-driven hunting |
| **Correlator** | Yes | Balanced | Link related alerts, build attack chain |
| **Responder** | No | Fast | Immediate action items, containment |
| **Reporter** | No | Balanced | Write-ups, executive summaries, PDF |
| **MITRE Analyst** | Yes | Balanced | ATT&CK mapping, technique details |
| **Forensics** | Yes | Thorough | Artifact analysis, chain of custody |
| **Threat Intel** | Yes | Balanced | IOC enrichment, actor profiling |
| **Compliance** | No | Balanced | Policy checks, regulatory alignment |
| **Malware Analyst** | Yes | Thorough | Behavioral analysis, sandbox results |
| **Network Analyst** | Yes | Balanced | Traffic analysis, C2 detection |
| **Auto-Responder** | Yes | Balanced | Autonomous actions (daemon mode) |

### Workflow Composition

```
INCIDENT RESPONSE WORKFLOW
  Triage ──► Investigator ──► Responder ──► Reporter
  (assess)   (root cause)    (contain)    (document)

FULL INVESTIGATION WORKFLOW
  Investigator ──► MITRE Analyst ──► Correlator ──► Responder ──► Reporter

THREAT HUNT WORKFLOW
  Threat Hunter ──► Network Analyst ──► Malware Analyst ──► Threat Intel ──► Reporter

FORENSIC ANALYSIS WORKFLOW
  Forensics ──► Malware Analyst ──► Network Analyst ──► Reporter
```

---

## Daily Analyst Routine

### Morning (First 30 Minutes)

```
1. Dashboard → Findings (filter: New, last 12h)
   └── Quick scan: any Critical? Overnight spikes?

2. Approval Queue
   └── Review pending agent actions from overnight daemon

3. Vigil Assistant: "Summarize overnight activity and top 3 priorities"
   └── Gets AI-synthesized briefing with live alert data
```

### During-Day Operations

```
4. New critical alert arrives
   └── Click → Run Triage Agent → review result (30 sec)
   └── If confirmed: Run Investigator Agent (2–5 min)
   └── If incident: Promote to Case → assign

5. Investigation in progress
   └── Chat with Investigator: "What other hosts may be affected?"
   └── Agent calls sentinelone_search_alerts, sentinelone_powerquery
   └── Results feed back automatically — no copy-paste

6. Ready to respond
   └── Responder Agent output → review containment actions
   └── Approve high-confidence actions → executed via MCP
   └── Document in case resolution steps
```

### End of Day

```
7. Vigil Assistant: "Generate today's incident summary"
   └── Counts, severities, actions taken, cases opened

8. Any open cases → add resolution notes
   └── Case → Resolution tab → Add Step

9. Weekly (Friday): "Generate board brief for this week"
   └── PDF-ready executive summary
```

---

## Security Posture

### No Hardcoded Credentials

All credentials flow through exactly one path:

```
UI form
  │
  set_secret(key, value)
        │
        ├──► ~/.vigil/secrets.enc   (AES-encrypted, persists restarts)
        │
        └──► os.environ              (in-process, for current session)
                    │
                    └── MCP subprocess inherits via ${VAR} substitution
```

No API keys in:
- Source files
- Database tables
- Log output
- Docker environment variables
- `.env` file (only non-secret config goes there)

### Integration Health Check

```bash
# Check which integrations are active and have valid credentials
curl http://localhost:6987/api/integrations/status

# Check which MCP tools are loaded
curl http://localhost:6987/api/agents/custom/_meta/tools | python -m json.tool
```

### Verify SentinelOne is Connected

```bash
curl http://localhost:6987/api/agents/custom/_meta/tools | \
  python -c "import sys,json; tools=json.load(sys.stdin); \
  s1=[t for t in tools if 'sentinelone' in t['name']]; \
  print(f'SentinelOne tools: {len(s1)}')"
# Expected: SentinelOne tools: 33
```

---

*Generated by Vigil SOC — 2026*
