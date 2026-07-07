---
name: sentinelone-sop
description: "SentinelOne SOP: four-phase workflow — Initial Triage → Investigation → Recommendations → Reporting — covering all SentinelOne Threats and Alerts across every monitored Site, Group, and Account."
agents:
  - triage
  - investigator
  - responder
  - reporter
tools-used:
  - get_finding
  - list_findings
  - nearest_neighbors
  - sentinelone_get_alert
  - sentinelone_list_alerts
  - sentinelone_search_alerts
  - sentinelone_powerquery
  - sentinelone_purple_ai
  - virustotal_get_file_report
  - virustotal_get_file_behaviour_summary
  - virustotal_get_file_relationship
  - virustotal_get_ip_report
  - virustotal_get_domain_report
  - virustotal_get_url_report
  - virustotal_search_vt
  - get_technique_rollup
  - create_attack_layer
  - create_approval_action
  - create_case
  - update_case
  - get_case
  - escalate_case
use-case: "End-to-end SentinelOne SOP handling for Threats (Static AI, Behavioral AI, Reputation, Application Control) and Alerts (STAR rules). Analyst must complete all four phases for every alert."
trigger-examples:
  - "Run SentinelOne SOP on finding s1-2513171305462730775"
  - "SentinelOne SOP for this alert"
  - "Run sentinelone-sop workflow on finding s1-XXXX"
  - "SOP investigation for this S1 threat"
  - "Full SOP for this SentinelOne detection"
---

# SentinelOne SOP Workflow

Follows the SentinelOne Standard Operating Procedure for all Threats and Alerts.
Scope: every SentinelOne detection across all monitored Sites, Groups, and Accounts —
Threats (Static AI, Behavioral AI, Reputation, Application Control, Documents/Lateral
Movement engines) and Alerts (STAR custom detection rules).

**The analyst must complete all four phases for every alert.**

---

## Agent Sequence

### Phase 1: Initial Triage (Triage Agent)

**Purpose (SOP §3):** Gather every relevant contextual data point and artifact that
supports the investigation.

**Tools:** `get_finding`, `sentinelone_search_alerts`, `virustotal_get_file_report`,
`virustotal_get_ip_report`, `virustotal_get_domain_report`,
`list_findings`, `nearest_neighbors`, `get_technique_rollup`

**Steps:**

**3.1 Capture Alert Details**
1. Call `get_finding` with the finding_id to retrieve the Vigil finding record
2. Extract and record:
   - Threat / Alert ID — use the `external_id` field (numeric, e.g. `2513171305462730775`), NOT the Vigil `finding_id` (which has the `s1-` prefix)
   - Detection timestamp and reported time
   - Threat name and classification (Malware, Ransomware, PUA, Exploit, etc.)
   - Detection engine / source (Static AI, Behavioral AI, Reputation, Application Control, STAR rule)
   - Confidence level (Malicious / Suspicious)
   - Severity
   - Mitigation status (Mitigated / Not Mitigated / Pending)
   - Incident status
   - Storyline ID
3. Call `sentinelone_search_alerts` with `filters: [{"fieldId": "id", "filterType": "fulltext", "values": ["<external_id>"]}]` (the numeric threat/alert ID from `external_id`) to retrieve the raw SentinelOne alert record.
   NOTE: `sentinelone_get_alert` expects a UUID internal ID (not the numeric `external_id`) and will fail if called with the numeric ID or the `s1-` prefixed finding_id.
   NOTE: `sentinelone_list_alerts` has no ID-based filter at all (only pagination + an assignment `view_type` filter) — it cannot target a specific finding and is not a usable substitute here.
   NOTE: only filter `sentinelone_search_alerts` on `id`, `severity`, `status`, `alertName`, `detectedAt`/`createdAt`, `analystVerdict`, `assigneeUserId`/`assigneeFullName`, `alertNoteExists`, or `storylineId` — filtering on `description` errors on this deployment's SentinelOne tenant with "Field description does not exist or not supported for FILTER API call", even though the tool's own docstring lists it as a valid field.
   NOTE: the `fields` parameter (which columns to return) uses a DIFFERENT, separate allowlist than the filter fields above — do not reuse filter-field names here. Valid `fields` values are exactly: `id`, `name` (not `alertName`), `severity`, `status`, `classification`, `confidenceLevel`, `detectedAt`, `firstSeenAt`, `lastSeenAt`, `description`, `analystVerdict`, `storylineId`, `externalId`, `ticketId`, `noteExists`, `result`, `dataSources`, `detectionSource { product vendor }`, `asset { id name type }`, `assignee { userId email fullName }` (nested selector — not a flat `assigneeFullName`). If `fields` is omitted, the tool returns its default field set, which is sufficient for this step — prefer omitting `fields` entirely over guessing a name.

**3.2 Capture Endpoint & Identity Context**
4. From the finding and alert data, extract:
   - Endpoint / Agent name and Agent version
   - OS, version, and build
   - Site / Group / Account
   - Logged-in user
   - The user/account that executed/performed the activity

**3.3 Collect Artifacts**
5. From the finding's entity_context and SentinelOne alert data, collect:
   - **File hashes — IMPORTANT:** The `get_finding` result includes an `entity_context` object. Read `entity_context.file_hashes` — it is an array of hash strings. Identify each hash by its length:
     - 32 characters = MD5
     - 40 characters = SHA1
     - 64 characters = SHA256 ← **use this for all VirusTotal lookups**
     Record the SHA256 (64-char hash), SHA1 (40-char), and MD5 (32-char). If `entity_context.file_hashes` is present, you MUST extract the SHA256 from it — do not skip this step.
   - **File:** Name, full path (from `entity_context`), size, signer/publisher, signature validity
   - **Process:** Process name, PID, full command line, parent process + parent command line, complete process tree
   - **Network:** Source/destination IPs, ports, domains, URLs (from `entity_context.network_connections` or `entity_context.remote_ips` / `entity_context.remote_domains`)
   - **Persistence:** Registry run keys, scheduled tasks, services, WMI subscriptions, startup entries
   - **Storyline:** Full event chain associated with the Storyline ID, any dropped/created/modified files, scripts, or modules

**3.4 Initial Enrichment**
6. Call `virustotal_get_file_report` with the SHA256 hash extracted from `entity_context.file_hashes` in step 5 above (the 64-character string). This is mandatory — if `entity_context.file_hashes` is present, always call this. Get the VirusTotal reputation verdict (detection ratio, malicious/suspicious vendor count, file type, size, first/last seen).
7. Call `virustotal_get_ip_report` for each external destination IP found in `entity_context.remote_ips`, `entity_context.network_connections`, or the SentinelOne alert data. **Only call this if a valid IP address string is present — skip if the IP is null, empty, or an internal/RFC-1918 address (10.x, 172.16–31.x, 192.168.x).**
8. Call `virustotal_get_domain_report` for each domain found in `entity_context.remote_domains`, `entity_context.dns_requests`, or the SentinelOne alert data. **Only call this if a valid non-empty domain string is available — skip if null or empty.**
9. Call `get_technique_rollup` to map any MITRE ATT&CK technique IDs from the SentinelOne indicators
10. Call `list_findings` filtered to the same hostname to check prior alerts on the same endpoint (last 90 days)
11. Call `nearest_neighbors` to find similar findings by embedding similarity (same hash or same user across the environment)

**Output:** Complete alert data record (3.1–3.3) + enrichment results (3.4):
verdict from hash reputation, IP/domain reputation, MITRE technique list,
prior alert count on same host/user/hash, prevalence across the environment.

---

### Phase 2: Investigation (Investigator Agent)

**Purpose (SOP §4):** Determine whether the observed activity is malicious, benign,
or inconclusive.

**Tools:** `get_finding`, `sentinelone_powerquery`, `sentinelone_purple_ai`,
`virustotal_get_file_report`, `virustotal_get_file_behaviour_summary`,
`virustotal_get_file_relationship`,
`virustotal_get_ip_report`, `virustotal_get_domain_report`, `virustotal_get_url_report`,
`nearest_neighbors`, `get_technique_rollup`, `create_attack_layer`

**Steps:**

**4.1 File Analysis**
1. Call `virustotal_get_file_report` with the SHA256 hash from `entity_context.file_hashes` (the 64-character entry). If not already retrieved in Phase 1, call `get_finding` again to read `entity_context.file_hashes` and extract the SHA256 now. Determine:
   - Detection ratio (e.g. 32/72 engines flagged as malicious)
   - Reputation verdict: known-good, known-bad, or unknown
   - File type, size, first/last submission date
   - Path legitimacy — is the file running from a normal location (Program Files, System32)
     or a suspicious one (Temp, AppData, Downloads, ProgramData, Recycle Bin)?
   - **Signature trust:** using the signer/publisher and signature-validity fields captured in
     Phase 1 (3.3), judge whether this is signed by a trusted, recognizable publisher with a
     valid signature — or unsigned/invalid/signed by an unknown or suspicious publisher.
   - **Masquerading / packing indicators:** does the filename impersonate a legitimate system
     binary while running from the wrong path (e.g. `svchost.exe` outside `System32`)? Does the
     VirusTotal report or behaviour summary show packing/obfuscation indicators inconsistent
     with the file's claimed identity?
2. Call `virustotal_get_file_behaviour_summary` for dynamic sandbox behavior (process creation, network, registry, dropped files)
3. Call `virustotal_get_file_relationship` to find related samples, dropped files, or parent droppers

**4.2 Process & Command-Line Analysis**
4. Call `sentinelone_powerquery` to retrieve process events for the Storyline ID. Analyze:
   - Parent ↔ child lineage — is the parent expected? (Office spawning PowerShell or cmd is suspicious)
   - Command-line inspection — encoded/obfuscated commands, download cradles, suspicious flags
   - LOLBin abuse — powershell, rundll32, mshta, wmic, certutil, regsvr32, bitsadmin
   - Execution context — user vs SYSTEM, unexpected privilege escalation

**4.3 Storyline Analysis**
5. Call `sentinelone_powerquery` with the Storyline ID to retrieve the full event chain. From trigger event through all subsequent actions:
   - Identify the root cause / initial access vector
   - Map the action sequence to attack stages: Execution → Persistence → Privilege Escalation → Defense Evasion → C2 → Exfiltration
6. Call `sentinelone_purple_ai` for an AI-assisted storyline summary if available
7. Call `get_technique_rollup` and `create_attack_layer` to produce the MITRE ATT&CK technique mapping for all observed techniques

**4.4 Persistence & Lateral Movement Analysis**
8. From the Storyline and process data, assess:
   - Where the artifact resides and whether it establishes persistence
   - Registry run keys, scheduled tasks, new services, startup folder entries, WMI
9. Perform lateral movement check: WinRM execution, LSASS access, RDP connections to many, LOLBin abuse
10. Call `nearest_neighbors` to sweep for the same malicious indicators across all endpoints — assess impact radius

**4.5 Network Analysis**
11. Call `virustotal_get_ip_report` for each destination IP collected in Phase 1 or from `sentinelone_powerquery` results — **only if a valid, non-empty, non-RFC-1918 IP string is available.** Assess:
    - Connections to known-bad or newly registered infrastructure
    - Beaconing / periodic callbacks indicative of C2
    - Outbound data volume suggesting exfiltration
12. Call `virustotal_get_domain_report` for each domain collected — **only if a valid, non-empty domain string is available.**
13. Call `virustotal_get_url_report` for any URLs extracted from the command line or network events — **only if a valid, non-empty URL string is available.**

**Determine Verdict:** Based on the complete analysis, assign one of three verdicts:
- **True Positive (TP)** — confirmed malicious activity
- **False Positive (FP)** — confirmed benign / legitimate activity
- **Validation Required** — inconclusive; specific evidence gaps must be identified

**Output:** Full investigation findings covering 4.1–4.5, MITRE ATT&CK layer,
verdict (TP / FP / Validation Required), impact radius, evidence chain.

---

### Phase 3: Recommendations (Responder Agent)

**Purpose (SOP §5):** Provide remediation actions aligned with the investigation verdict.

**Tools:** `get_finding`, `create_approval_action`, `update_case`

**Steps:**

1. Review the investigation output — verdict, evidence chain, impact radius, MITRE techniques

2. **If TRUE POSITIVE — recommend all applicable response actions:**
   - **Mitigate the threat** — confirm whether the malicious file/process has been quarantined
     or removed from the affected endpoint (check mitigation status from triage)
   - **Block the identified IOCs** — recommend blocking the hash, IP, domain, and URL across
     firewall, proxy, email gateway, and EDR. Submit via `create_approval_action` with the
     specific IOCs and confidence score
   - **Eradicate persistence** — review and remove the malicious persistence identified in the
     investigation (registry run keys, scheduled tasks, services, startup entries)
   - **Close the control gap (hardening)** — recommend preventive controls to reduce recurrence:
     disable Office macros / restrict script execution / enforce application control / etc.
   - If confidence ≥ 0.90: submit auto-approvable `create_approval_action` for containment
   - If confidence 0.70–0.89: submit `create_approval_action` requiring analyst approval

3. **If FALSE POSITIVE — recommend tuning actions:**
   - Tuning/exclusion suggestions to reduce recurrence
   - Confirmation steps to formally close the alert
   - Document the FP reasoning for future triage learning

4. **If VALIDATION REQUIRED — identify exactly what is needed:**
   - Legitimacy of the file/activity — does the customer recognise this as a known, legitimate
     part of their environment?
   - Whether it was known and authorized — was this performed by an authorized user/admin or
     part of a planned/approved change, maintenance window, or sanctioned tool?
   - List specific evidence gaps that must be closed to reach a TP or FP verdict

**Output:** Verdict-aligned recommendations, approval actions submitted (TP), FP tuning
suggestions (FP), or specific validation questions (Validation Required).

---

### Phase 4: Reporting (Reporter Agent)

**Purpose (SOP §6):** Produce the final output in three sections, following the SOP order,
then document and escalate per SOP §2 ("Document a case ... Escalate it to customer").

**Tools:** `get_finding`, `get_case`, `create_case`, `escalate_case`, `list_findings`

**Steps:**

1. Call `get_finding` to retrieve the fully enriched finding record
2. Compile all outputs from Phases 1–3

3. Generate the final report in exactly this structure:

---

## Incident Report — [Finding ID] — [Hostname] — [Date]

### 6.1 Alert Details

| Field | Value |
|---|---|
| Threat / Alert ID | |
| Threat Name | |
| Classification | |
| Confidence Level | Malicious / Suspicious |
| Severity | |
| Detection Timestamp | |
| Reported Time | |
| Storyline ID | |
| Mitigation Status | Mitigated / Not Mitigated / Pending |
| Incident Status | |
| Endpoint | hostname (Agent version) |
| OS | version + build |
| Site / Group / Account | |
| Logged-in User | |
| Executing User | |
| Detection Engine | Static AI / Behavioral AI / Reputation / Application Control / STAR |
| Key File | name, full path, SHA256, MD5, size |
| Key Process | process name, PID, command line, parent process |
| Network Destinations | IPs, ports, domains, URLs |

### 6.2 Analysis and Impact

**Verdict:** True Positive / False Positive / Validation Required

**Investigation Summary:** [Narrative summarising the investigation findings and
supporting evidence/reasoning — what the activity did or could do]

**MITRE ATT&CK Techniques Observed:**
| Technique ID | Name | Tactic |
|---|---|---|
| T1XXX.XXX | … | … |

**Impact Assessment:**
- What the activity did or could have done
- Assets affected
- Scope: single host vs multiple hosts / lateral movement
- [If Validation Required: describe the specific evidence gaps to close or further investigate]

### 6.3 Recommendations

[Populate based on verdict:]

**For True Positive:**
- Mitigate the threat: [specific action + confirmation of quarantine status]
- Block IOCs: [hash, IPs, domains, URLs — across firewall/proxy/email gateway/EDR]
- Eradicate persistence: [specific registry keys / scheduled tasks / services to remove]
- Harden: [specific preventive control recommendation]

**For False Positive:**
- Tuning / exclusion: [what to exclude and how]
- Confirmation: [steps to close the alert]

**For Validation Required:**
- [Specific question 1 — e.g., "Is process X a known legitimate tool in this environment?"]
- [Specific question 2 — e.g., "Was this change performed during an approved maintenance window?"]

---

4. **VERDICT GATE — do this before calling any tool in this step.** Re-read the exact
   **Verdict** string you just wrote in section 6.2. It is one of three values:
   `True Positive`, `False Positive`, or `Validation Required`. Compare it literally:
   - Verdict is **exactly** `True Positive` → proceed to step 4a below.
   - Verdict is `False Positive` or `Validation Required` → **stop here.** Skip step 4a
     entirely and go straight to step 5. Do not call `create_case` or `escalate_case` —
     not even to "document" or "flag for visibility." Those two tools are TP-only. Calling
     them for a non-TP verdict is a SOP violation regardless of how you justify it in the
     call arguments.

   **4a. TRUE POSITIVE only** — call `create_case` with:
   - `title`: `"TP: [threat_name] on [hostname]"` — the `TP:` prefix is only valid here,
     because you already confirmed the verdict is exactly True Positive
   - `description`: the full report (sections 6.1–6.3 above), verbatim — not a shortened summary
   - `severity`: **required by this tool — never omit it.** Map from the Severity captured in
     Phase 1 (3.1): `"critical"` if Severity is Critical, `"high"` if High, `"medium"` if Medium,
     `"low"` if Low/Informational
   - `finding_ids`: `["<finding_id>"]` — an array containing the Vigil finding_id (the `s1-`
     prefixed one from Phase 1), NOT the numeric `external_id`
   Then call `escalate_case` on the newly created case to notify the account owner (SOP §2: "Escalate it
   to customer"):
   - `escalated_from`: `"vigil-ai-sentinelone-sop"`
   - `escalated_to`: the Site / Group / Account captured in Phase 1 (3.2) if available, otherwise
     `"soc-manager"`
   - `reason`: one-line summary of the verdict (e.g. `"Confirmed malware on <hostname>: <threat_name>"`)
   - `urgency_level`: `"critical"` if Severity is Critical/High, otherwise `"high"` — a confirmed
     True Positive is never escalated below `"high"`
5. **If FALSE POSITIVE or VALIDATION REQUIRED (per the gate in step 4):** Do not auto-create a
   case and do not escalate — the finished report text (6.1–6.3) IS the deliverable for these
   two verdicts. Note the outcome for analyst review and end the workflow here.

**Output:** Completed SOP report (sections 6.1 / 6.2 / 6.3). `case_id` and escalation record
ONLY when the verdict gate in step 4 confirmed True Positive — absent for False Positive /
Validation Required.

---

## Example Invocations

```
Run SentinelOne SOP on finding s1-2513171305462730775
```

```
SentinelOne SOP for finding s1-2513171305462730775 — endpoint NPHYDLPT0105
```
