# Port Scan Reconnaissance - Incident Response Playbook

## Overview

A playbook is a comprehensive, documented set of procedures and protocols that guides security teams on how to respond to specific security incidents and threats. This playbook provides step-by-step instructions for SOC L1 analysts to detect, investigate, contain, and escalate port scanning and reconnaissance attempts.

**When to Use This Playbook:**
- Dashboard alert fires for reconnaissance activity
- Single source exceeds probe threshold
- Multiple scanning sources detected
- Any network reconnaissance traffic identified

**Playbook Scope:** Network reconnaissance detection and response  
**Severity:** CRITICAL to LOW (tiered response)  
**On-Call Team:** SOC L1 → SOC L2 → Threat Intelligence

---

## Alert Trigger Conditions

This playbook activates when the following thresholds are exceeded:

| Time Window | Probe Count | Trigger Status |
|------------|-------------|----------------|
| Per minute | > 100 | 🔴 CRITICAL - Activate playbook immediately |
| Per minute | 50-100 | 🟡 HIGH - Investigate within 5 minutes |
| Per minute | 20-50 | 🟠 MEDIUM - Monitor and investigate |
| Per minute | 5-20 | 🟢 LOW - Normal baseline, monitor only |
| Per minute | < 5 | ✅ NORMAL - No action needed |

**Detection Signals:**
- Dashboard KPI shows >500 total probes from single source
- "Scanning Sources & Status" table shows 🔴 Active status
- Volume & Detection graph shows sustained spike >50/min
- Connection state REJ (rejection) dominates (>99%)

**Verification Query:**
```spl
index=main sourcetype="_json"
| bucket _time span=1m
| stats count as probes_per_minute by source_ip, _time
| where probes_per_minute > 100
```

---

## Severity Levels

### CRITICAL (>500 total probes OR >100 probes/minute)
- **Indicator:** Automated scanner detected
- **Response:** Immediate containment + escalation
- **Timeline:** Respond within 5 minutes
- **Action:** Block IP + Create P1 ticket + Escalate to SOC L2
- **Example:** 192.168.1.11 with 2,019 probes in 2 minutes

### HIGH (100-500 total probes OR 50-100 probes/minute)
- **Indicator:** Aggressive reconnaissance
- **Response:** Investigate + Containment
- **Timeline:** Respond within 15 minutes
- **Action:** Block IP + Investigate source + Check for exploitation attempts
- **Example:** Unknown IP with 250 probes to multiple ports

### MEDIUM (50-100 total probes OR 20-50 probes/minute)
- **Indicator:** Suspicious but controlled scanning
- **Response:** Investigate + Monitor
- **Timeline:** Respond within 30 minutes
- **Action:** Whitelist verification + Monitor for follow-up activity
- **Example:** Known scanner with unusual port targets

### LOW (20-50 total probes)
- **Indicator:** Elevated but potentially legitimate
- **Response:** Monitor + Baseline verification
- **Timeline:** Investigate within 1 hour
- **Action:** Check if source is authorized + Update whitelist if legitimate
- **Example:** Scheduled vulnerability scan from known IP

---

## Immediate Actions (0-5 minutes)

### Step 1: Verify Alert (1 minute)
**Action:** Confirm the alert is real, not false positive

```spl
index=main sourcetype="_json" 
| bucket _time span=1m 
| stats count as total_probes by source_ip, _time
| where total_probes > 100
| sort - total_probes
```

**What to Check:**
- Is probe count consistently >100/min?
- Is it from single IP or multiple sources?
- Did it start recently or ongoing?

**Record:**
- Screenshot dashboard showing alert
- Note exact time alert triggered
- Document source IP and probe count

### Step 2: Identify Attacker (1 minute)
**Action:** Extract source IP from "Scanning Sources & Status" table

**Information Needed:**
- Attacker source IP: `________________`
- Total probes: `________________`
- First seen: `________________`
- Status: 🔴 CRITICAL / 🟡 HIGH / 🟠 MEDIUM

### Step 3: Whitelist Check (1 minute)
**Action:** Determine if source IP is authorized

```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>"
| stats count by source_ip
```

**Check Against Known Authorized Scanners:**
- Nessus vulnerability scanner? NO / YES
- Qualys continuous monitoring? NO / YES
- Internal pentest team? NO / YES
- Load balancer health checks? NO / YES
- **If YES:** Document and skip to section "Legitimate Scanning" at end
- **If NO:** Proceed to Step 4

### Step 4: Screenshot & Document (1 minute)
**Action:** Preserve evidence immediately

**Take Screenshots Of:**
1. Dashboard overview (all panels visible)
2. "Scanning Sources & Status" table
3. "Volume & Detection" area graph
4. Attack timeline showing spike

**Save to:** `/incident-response/[DATE]-[SOURCE_IP]-alert.png`

### Step 5: Create Ticket (1 minute)
**Action:** Open incident ticket in JIRA/ServiceNow

**Ticket Template:**
Title: Port Scan Reconnaissance - [SOURCE_IP] Attacking [TARGET_IP]
Severity: CRITICAL / HIGH / MEDIUM
Assigned To: [Your Name]
Created: [Date/Time]
Description:

Attacker IP: [SOURCE_IP]
Target IP: [TARGET_IP]
Total Probes: [COUNT]
Duration: [START - END TIME]
Scan Type: Nmap reconnaissance (SYN/UDP/Version/OS/ACK)
Status: OPEN - Under Investigation

Dashboard Evidence:

[Attach screenshots]
[Detection query results]


---

## Investigation Phase (5-30 minutes)

### Step 1: Analyze Attack Pattern (5 minutes)
**Action:** Determine attack type and scope

**Query: Scan Type Detection**
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>" target_ip="<TARGET_IP>"
| stats count by conn_state
| sort - count
```

**Expected Results:**
- **REJ dominant (>99%)** = Port scan (target rejecting connections)
- **RSTO present** = Attacker resetting connections
- **S0 present** = SYN scan detected
- **SF minimal** = Few successful connections

**Record Finding:**
- Scan Type Detected: `SYN / UDP / Version / OS / ACK`
- Connection States: `REJ / RSTO / S0 / SF`
- Ports Targeted: `[List top 5]`

### Step 2: Check Ports Targeted (5 minutes)
**Action:** Identify which services attacker was probing

**Query: Top Targeted Ports**
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>" target_ip="<TARGET_IP>"
| stats count by target_port
| sort - count
| head 10
```

**Critical Ports to Monitor:**
- Port 22 (SSH) - High value target
- Port 3306 (MySQL) - Database access
- Port 5432 (PostgreSQL) - Database access
- Port 445 (SMB) - Windows file sharing
- Port 3389 (RDP) - Remote desktop

**Risk Assessment:**
- ✅ Only common ports scanned = Normal reconnaissance
- ⚠️ Specific high-value ports targeted = Targeted attack
- 🔴 All ports 1-65535 scanned = Complete enumeration

### Step 3: Check for Exploitation Attempts (10 minutes)
**Action:** Verify attacker didn't successfully compromise target

**Query: Successful Connections from Attacker**
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>" target_ip="<TARGET_IP>" conn_state="SF"
| stats count, values(target_port) as ports_connected by source_ip
```

**What to Check:**
- Are there ANY successful connections (SF state)?
- If SF count > 0: Which ports? (22, 3306, etc.)
- Timestamp: When did successful connection occur?

**If Successful Connection Found:**
- 🔴 **ESCALATE IMMEDIATELY** to SOC L2
- Likely successful exploitation attempt
- Requires deeper forensic analysis

### Step 4: Timeline Reconstruction (10 minutes)
**Action:** Build attack timeline for incident report

**Query: Attack Timeline**
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>" target_ip="<TARGET_IP>"
| bucket _time span=2m
| stats count as probes by _time
| table _time, probes
```

**Document:**
- 10:08 UTC - Version detection scan (1,001 probes)
- 10:10 UTC - OS fingerprinting scan (1,018 probes)
- 10:12 UTC - Follow-up probing (if any)
- Duration of attack: _____ minutes

**Analysis:**
- Two distinct scanning waves suggests **multi-stage attack**
- Attacker iterating on reconnaissance = **persistence**

---

## Containment Actions (30-60 minutes)

### Action 1: Block Attacker IP at Firewall (Immediate)

**Contact:** Network Operations Team / Firewall Admin

**Request:**
Block traffic from [SOURCE_IP] to [TARGET_IP]

Direction: Inbound
All ports: Block
Duration: Until further notice
Reason: Port scan reconnaissance attack detected

Supporting Evidence:

Dashboard alert: [Link]
JIRA Ticket: [Ticket #]


**Verification:**
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>" target_ip="<TARGET_IP>" 
| where _time > now-10m
| stats count as recent_probes
```
Expected: recent_probes = 0 (no activity after block)

### Action 2: Scan Target for Backdoors (15 minutes)

**If NO successful connections (SF state):**
- Attacker likely didn't compromise system
- **Action:** Monitor target system for next 24 hours
- No immediate remediation needed

**If successful connections detected:**
- **ESCALATE to SOC L2 immediately**
- Potential system compromise
- Requires malware/backdoor analysis

### Action 3: Check for Lateral Movement (10 minutes)

**Query: Is attacker scanning other targets?**
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>"
| stats count as probes, values(target_ip) as targets by source_ip
| eval target_count=mvcount(targets)
| where target_count > 1
```

**If Multiple Targets Found:**
- 🔴 Attacker scanning network = **Escalate**
- Possible network-wide reconnaissance
- Multiple systems at risk

**If Single Target:**
- ✅ Targeted attack on specific system
- Lower scope = Easier to contain

### Action 4: Monitor for Follow-Up Activity (15 minutes)

**Query: Watch for immediate re-attack**
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>" target_ip="<TARGET_IP>"
| where _time > now-15m
| stats count as recent_probes
```

**Continue Monitoring:**
- Next 24 hours: Check every 4 hours
- Next 7 days: Check daily
- Next 30 days: Weekly review

---

## Escalation Criteria

### Escalate to SOC L2 Immediately If:

1. **Successful Connection Detected** (conn_state="SF")
   - Attacker may have gained access
   - Requires forensic analysis
   - **Action:** Open P1 ticket + Call on-call L2

2. **Multiple Targets Scanning**
   - Network-wide reconnaissance
   - Suggests organized attack
   - **Action:** Escalate + Network team involvement

3. **Critical Port Targeted Successfully**
   - Port 22 (SSH), 3306 (MySQL), 445 (SMB), 3389 (RDP)
   - High-value target = High impact
   - **Action:** Immediate L2 escalation

4. **Internal IP Scanning**
   - source_ip = Internal network (insider threat)
   - Compromised internal system attacking others
   - **Action:** Isolate source system + Escalate

5. **Sustained Attack > 1 hour**
   - Continuous probing over extended period
   - Indicates persistence/determination
   - **Action:** Escalate + Threat Intel involvement

6. **Source IP Known Malicious**
   - Previous attacks from same IP
   - APT attribution possible
   - **Action:** Escalate + Threat Intel analysis

### Escalation Contact:
- **SOC L2 On-Call:** [Phone number / Slack]
- **Threat Intelligence:** [Email / Slack]
- **Network Ops:** [Phone / On-call]

---

## Evidence Preservation

### Screenshots to Save:
1. Dashboard overview (timestamp visible)
2. Scanning Sources & Status table
3. Volume & Detection graph
4. All SPL query results

**Save To:**
/security/incidents/[YYYY-MM-DD]-[SOURCE-IP]-reconnaissance/
├── dashboard-overview.png
├── scanning-sources.png
├── volume-timeline.png
├── query-results.txt
└── incident-ticket-[JIRA-ID].txt

### Logs to Export:
```spl
index=main sourcetype="_json" source_ip="<ATTACKER_IP>" target_ip="<TARGET_IP>"
| fields _time, source_ip, target_ip, target_port, conn_state, proto, service
| export > incident_logs.csv
```

### Documentation to Keep:
- Initial alert screenshot
- All SPL queries run
- Investigation findings
- Firewall block confirmation
- Ticket history (JIRA/ServiceNow)

---

## Closure Criteria

### Incident is RESOLVED when:

✅ **Block Confirmed**
- Firewall confirms IP is blocked
- Recent probe query returns 0 results

✅ **No Exploitation Detected**
- All connections show REJ/RSTO (rejected)
- No SF (successful connection) state
- Target system integrity verified

✅ **Monitoring Complete**
- 24-hour observation period passed
- No new probes from attacker IP
- No follow-up scanning detected

✅ **Documentation Complete**
- Incident ticket updated with findings
- All evidence preserved
- Lessons learned documented

### Closure Steps:

1. **Update JIRA Ticket:**
Status: RESOLVED
Resolution: Attacker IP blocked, no compromise detected
Monitoring: 24-hour surveillance complete - no follow-up
Evidence: [Link to incident folder]

2. **Send Summary Email:**
To: SOC Lead / Security Manager
Subject: Incident Closed - Port Scan [SOURCE_IP] [JIRA-ID]
Summary:

Attack Type: Port scan reconnaissance
Duration: [TIME WINDOW]
Result: Blocked, no compromise
Action Taken: Firewall block, 24-hour monitoring


3. **Archive Evidence:**
   - Move to long-term storage
   - Label with incident ID
   - Reference in JIRA

---

## Contact List

### SOC Escalation Hierarchy:

| Level | Role | Contact | Response Time |
|-------|------|---------|----------------|
| **L1** | SOC Analyst (You) | - | Immediate |
| **L2** | Senior Analyst | [On-call #] or [Slack] | 5 minutes |
| **L3** | Security Incident Manager | [Phone] | 15 minutes |
| **L4** | CISO / Exec | [Email] | 1 hour |

### Team Contacts:

**Network Operations (Firewall):**
- Name: _______________
- Phone: _______________
- Email: _______________
- Slack: _______________

**Threat Intelligence:**
- Name: _______________
- Email: _______________
- Slack: _______________

**System Administration (Target Server):**
- Name: _______________
- Phone: _______________
- Email: _______________

---

## Appendix: Quick Reference

### Alert Severity Quick Guide:
- >500 probes = 🔴 CRITICAL (block immediately)
- 100-500 probes = 🟡 HIGH (investigate)
- 50-100 probes = 🟠 MEDIUM (monitor)
- <50 probes = 🟢 LOW (baseline)

### Key Queries Cheat Sheet:

**Verify Alert:**
```spl
index=main sourcetype="_json" | bucket _time span=1m | stats count as probes by source_ip, _time | where probes > 100
```

**Get Attacker Details:**
```spl
index=main sourcetype="_json" source_ip="<IP>" | stats count as total_probes, values(target_ip) as targets, values(target_port) as ports by source_ip
```

**Check for Exploitation:**
```spl
index=main sourcetype="_json" source_ip="<IP>" conn_state="SF" | stats count
```

**Timeline:**
```spl
index=main sourcetype="_json" source_ip="<IP>" | bucket _time span=2m | stats count by _time
```

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | May 2026 | Shourya | Initial playbook creation |

**Last Updated:** May 2026  
**Next Review:** August 2026

---

**Questions?** Contact SOC Lead or create GitHub issue on port-scan-detection repo.