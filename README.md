# Microsoft-30Day-SOC-Challenge
A 30-day journey through real-world SOC operations using Microsoft security tools. Includes KQL queries, incident response workflows, and reflections on building modern cloud detections.

## Overview
This repository documents my journey through the **MyDFIR Microsoft 30-Day SOC Analyst Challenge**, where I built, configured, and analyzed a Microsoft SOC environment using **Sentinel**, **Defender XDR**, and **Entra ID**.


## Table of Contents
- [Day 1 – Lab Setup & Planning](Day1-Lab-Setup-and-Planning/README.md)
- [Day 2 – Virtual Machine Setup](Day2-Virtual-Machine-Setup/README.md)
- [Day 3 – Sentinel Workspace Overview](Day3-Sentinel-Workspace-Overview/README.md)
- [Day 4 – KQL Queries](Day4-KQL-Queries/README.md)
- [Day 5 – Dashboard Creation](Day5-Dashboard-Creation/README.md)
- [Day 6 – Alert & Incident Creation](Day6-Alert-and-Incident-Creation/README.md)
- [Day 7 – Incident Investigation Report](Day7-Incident-Investigation-Report/README.md)
- [Day 8 – Bookmark & Manual Incident](Day8-Bookmark-and-Manual-Incident/README.md)
- [Resources](Resources/tools-list.md)

## Day 1 — Lab Setup and Planning

**Objective:**  
Create an Azure account, set up billing alerts, and define a resource naming convention.  
Plan out the lab structure and goals for the 30-Day Challenge.

**Tasks Completed:**  
- Created Microsoft Azure account and configured billing alert thresholds.  
- Defined resource naming convention (e.g., MyDFIR-Dean-Sentinel).  
- Outlined lab plan and estimated completion schedule.  

**Reflection (Placeholder):**  
Setting up the environment helped me understand Azure cost management and resource organization.  

## Day 2 — Virtual Machine Setup

**Objective:**  
Create a virtual machine in Azure or on-premises for use in the SOC lab.

**Tasks Completed:**  
- Deployed Windows 10 VM for endpoint simulation.  
- Configured network settings and baseline security policies.  
- Verified connectivity to Microsoft Sentinel workspace.  

**Reflection (Placeholder):**  
Learned how to spin up and secure virtual machines for monitoring and testing.  

**Screenshots:**  

## Day 3 — Sentinel Workspace Overview

**Objective:**  
Explore the Sentinel interface and familiarize with its tabs, features, and capabilities.

**Tasks Completed:**  
- Reviewed **Overview**, **Incidents**, **Logs**, **Hunting**, and **Workbooks** tabs.  
- Captured initial dashboard screenshot for future portfolio use.  

**Reflection (Placeholder):**  
Understanding Sentinel’s UI made it easier to navigate during later assignments.  

**Screenshots:**  

# Day 4 — KQL Queries

## Objective
Use KQL to query Microsoft Sentinel logs and identify authentication failures, event trends, and host activity patterns to strengthen detection and analysis capabilities.

---

## Tools & Concepts
- Microsoft Sentinel  
- Log Analytics Workspace  
- KQL (Kusto Query Language)  
- EventID 4625 (Failed Logon Events)  
- SOC Analysis & Detection

---

## Query 1 — Top Accounts with Failed Logons
```kql
SecurityEvent_CL
| where EventID_s == "4625"
| summarize FailedAttempts = count() by Account_s, AccountType_s
| top 10 by FailedAttempts desc
```
### Purpose:
Identify which accounts have the highest number of failed login attempts.
### Why It’s Important:
This helps detect brute-force or password-spraying attacks targeting user or admin accounts.

![Query 1 – Top Accounts with Failed Logons](Day4-KQL-Queries/screenshot/ms_30-day_challenge_ss-1.png)
### Observation:
Administrator accounts had an unusually high number of failed attempts, indicating potential credential-stuffing activity.

## Query 2 — Most Common Event IDs (Frequency Analysis)
```
SecurityEvent_CL
| summarize RandomCount = count() by EventID_s
| sort by RandomCount desc
```
### Purpose:
Show which Event IDs are most common in the dataset.
### Why It’s Important:
Helps analysts understand which event types dominate the log flow, giving context to noise vs. signal.

![Query 2 — Most Common Event IDs](Day4-KQL-Queries/screenshot/ms_30-day_challenge_ss-2.png)
### Observation:
Event ID 4625 (Failed Logons) appeared most frequently, confirming heavy authentication failure activity.


## Query 3 — Failed Logons by Computer and Account
```
SecurityEvent_CL
| where EventID_s == "4625"
| summarize FailedAttempts = count() by Computer, Account_s
| top 5 by FailedAttempts desc
```
### Purpose:
Correlate failed logon attempts with the computers where they occurred.
### Why It’s Important:
Reveals which systems are being targeted, supporting scoping and prioritization in investigations.

![Query 3 — Failed Logons by Computer and Account](Day4-KQL-Queries/screenshot/ms_30-day_challenge_ss-3.png)
### Observation:
The SOC-FW-RDP host had the highest failed logons, suggesting external RDP brute-force attempts.

# Day 5 — Dashboard Creation

## Objective
Add three panels to Microsoft Sentinel dashboard using different visualization types: bar, line, and pie.

---

## Tools & Concepts
- Microsoft Sentinel Workbooks  
- KQL Queries for visual data  
- Visualization Types: Bar • Line • Pie  

---

## Panel 1 – Failed Logons by Account (Pie Chart)

**Objective:**  
Identify which user accounts are experiencing the most failed login attempts by visualizing their proportion of total failures.

**KQL Query:**
```kql
SecurityEvent_CL
| where EventID_s == "4625"
| summarize Count = count() by Account_s
| sort by Count
| take 5
```
### Purpose:
Breaks down the top 5 accounts with the highest number of failed logon events (Event ID 4625).
Visualizing the data as proportions highlighting accounts that contribute most to the failed login volume.
### Why It’s Important:
- Quickly identifies high-risk or frequently attacked accounts.
- Useful for validating whether brute-force activity targets specific privileged users.
- Provides an at-a-glance metric for SOC dashboards or executive summaries.

![Panel 1 — Top 5 Failed Logons by Account ](Day5-Dashboard-Creation/screenshots/top-failed-login-pie.png)
### Observation:
Administrator-level accounts dominated the failed login attempts (`\ADMINISTRATOR, \admin, \administrator`), suggesting targeted password-guessing activity on privileged users.
This insight guides better alert tuning and reinforces defenses for privileged account credentials.

## Panel 2 – Event ID Count (Column Chart)

**Objective:**  
Visualize the frequency of different Windows Event IDs in the dataset to identify which event types occur most often.

**KQL Query:**
```kql
SecurityEvent_CL
| summarize Total = count() by EventID_s
| sort by Total asc
| take 15
| render columnchart
```

### Purpose:
This column chart displays the top 15 Event IDs and their frequency counts from security logs.
By visualizing event frequency, analysts can quickly determine which activities dominate the environment, which helps separate common background noise from potential anomalies.
### Why It’s Important:
- Reveals the most frequent system events (normal baseline behavior).
- Highlights rare or infrequent Event IDs that might indicate suspicious activity.
- Helps prioritize which logs to focus on for deeper analysis.

![Panel 2 — Event ID Count](Day5-Dashboard-Creation/screenshots/event-id-count-bar.png)
### Observation:
Event ID 5058 occurred the most, significantly higher than others like 4624 and 4625.
Can be used to help establish a baseline for normal system activity.

## Panel 3 – Failed Logons Over Time (Line Chart)

**Objective:**  
Visualize the trend of failed logon attempts across accounts over a specific time window.

**KQL Query:**
```kql
SecurityEvent_CL
| extend EventTime = todatetime(replace_string(TimeCollected_UTC__s, ",", ""))
| where EventTime between (datetime(2021-04-16 00:00:00) .. datetime(2021-04-17 00:00:00))
| summarize FailedLogons = count() by bin(EventTime, 5m), Account_s
| order by EventTime asc
| render timechart
```
### Purpose:
This line chart tracks failed logon activity for each account in 5-minute intervals, helping analysts identify login bursts or anomalies across time.
### Why It’s Important:
- Reveals temporal patterns in brute-force or password-spray attempts.
- Helps correlate spikes in failed logons with specific attack windows.
- Enables proactive tuning of analytic rules and rate-based detections.
  
![Panel 3 — Failed Logons Over Time)](Day5-Dashboard-Creation/screenshots/failed-login-by-min-line.png)
### Observation:
The `\ADMINISTRATOR` account maintained consistently high failure counts, peaking around 03:35 AM, indicating repeated login attempts within a short period.
Other accounts like `\admin` and `\administrator` show similar spikes, supporting a likely password-spray pattern across multiple privileged users.

# Day 6 — Alert and Incident Creation

## Objective
Create a custom analytic rule in Microsoft Sentinel using KQL to detect multiple failed logon attempts and generate an alert when thresholds are exceeded.

---

## Tools & Concepts
- Microsoft Sentinel  
- Microsoft Defender XDR  
- KQL (Kusto Query Language)  
- Analytic Rules & Incidents  
- Detection Engineering  

---

## Detection Query
```kql
SecurityEvent_CL 
| where EventID_s == "4625" 
| summarize FailedLogons = count() by Account_s
| where FailedLogons >= 1000
```
### Purpose:
Detect accounts exceeding 1,000 failed logon attempts. A common indicator of brute-force or password-spray activity. 
### Why It’s Important:
- Failed logons are early indicators of brute-force or password-spray attacks.
- Detecting abnormal volumes helps identify unauthorized access attempts.
- Custom analytic rules in Sentinel enable proactive detection and alerting.
- Supports MITRE ATT&CK technique TA0006 – Credential Access.
![Alert 1000 — Failed Logons Over Time)](Day6-Alert-Incidents/screenshots/incident-alert.png)
### Observation:
The rule triggered several MyDFIR-ndean-FailedLogonAlert incidents (9–15 attempts), confirming the query worked.
In a real SOC, this would prompt a check for repeated failures or password-spray activity.

# Day 7 — Incident Investigation Report

## Objective
Investigate an alert generated from the “Multiple Failed Logons Detection” rule in Microsoft Sentinel to determine scope, impact, and recommended actions.

---

## Tools & Concepts
- Microsoft Sentinel  
- KQL (Query Language)  
- MITRE ATT&CK T1110 (Brute Force)  
- Incident Handling Lifecycle  

---

## Findings
**Alert Name:** Multiple Failed Logons Detected  
**Severity:** High  
**Event ID:** 4625 (Failed Logon)  
**Time Range:** 2024-04-16 08:34 UTC – 09:33 UTC  
**Affected Hosts:** `SHIR-Hive`, `SHIR-SAP`, `SOC-FW-RDP`  
**Targeted Accounts:** `\ADMINISTRATOR`, `\admin`, `\administrator`  

---

## Investigation Summary
On 2024-04-16 08:34 UTC, multiple failed logon attempts were detected from several hosts targeting privileged accounts.  
The activity pattern suggested a **brute-force or password-spray attack**.  
No successful logons (Event ID 4624) were observed, indicating the attempts were unsuccessful.  
The activity likely used automated credential guessing via RDP or network authentication.

---

##  WHO
**Hosts:** `SHIR-Hive`, `SHIR-SAP`, `SOC-FW-RDP`  
**Accounts Targeted:** Administrator accounts across multiple hosts  

![Host Activity](Day7-Incident-Investigation-Report/screenshots/ms-30Day_Challenge-7-1.png)

![Accounts Targeted](Day7-Incident-Investigation-Report/screenshots/ms-30Day_Challenge-7-2.png)

---

## WHAT
Failed attempts totaling **18,163** across the three hosts.

---

## WHEN
| Host | Time Range (UTC) |
|------|-------------------|
| SHIR-Hive | 2021-04-16 08:34 – 09:33 |
| SHIR-SAP | 2021-04-16 08:34 – 09:33 |
| SOC-FW-RDP | 2021-04-16 08:34 – 09:00 |

![Timeline Evidence](screenshots/when_activity.png)

Limited data to confirm if activity continued beyond this window.

---

## WHERE
Activity originated from internal hosts `SHIR-Hive`, `SHIR-SAP`, and `SOC-FW-RDP`,  
suggesting an attack via RDP or Windows authentication services.

---

## WHY
Likely an automated attacker attempting to gain access to privileged accounts via brute-force or password spray.  
If these hosts are internet-facing or relay services, external actors may be involved.

---

## HOW
Automated tool or script iterating credentials against accounts over RDP / domain authentication.  
The hostname `SOC-FW-RDP` indicates a remote desktop front end likely used for testing or management.

---

## Supporting KQL Queries
```kql
// Failed logons by host
SecurityEvent_CL
| where EventID_s == "4625"
| summarize FailedAttempts = count() by Computer, Account_s
| top 10 by FailedAttempts desc
```

# Day 8 — Bookmark & Manual Incident

## Objective
Use Microsoft Sentinel to identify a notable pattern in Office 365 activity logs, bookmark the finding, and create a manual incident for further investigation.

---

## Tools & Concepts
- Microsoft Sentinel  
- OfficeActivity_CL table  
- KQL (Kusto Query Language)  
- Bookmarks & Manual Incidents  
- SOC Investigation Workflow  

---

## KQL Query
```kql
OfficeActivity_CL
| where Operation_s == "FileAccessed"
```
### Purpose:
Retrieve Office 365 file-access events to review for unusual activity such as access from new or unexpected IP addresses.
### Why It's Important:
Manual incidents help analysts capture context that automated detections may miss.
They demonstrate the ability to:
- Recognize suspicious behavior during proactive log review
- Escalate findings with supporting evidence
- Maintain clear documentation for peer validation
![Bookmark Abnormal IP)](Day8-Bookmark-and-Manual-Incident/screenshots/ms_30-day_challenge-bookmark.png)
### Observation:
- The FileAccessed query showed activity from an unusual IP address.
- A bookmark was created for further review.
- May indicate suspicious or unauthorized access requiring investigation.

## MITRE ATT&CK Mapping
| Tactic            | Technique      | ID    |
| ----------------- | -------------- | ----- |
| Credential Access | Brute Force    | T1110 |
| Execution         | User Execution | T1204 |
| Defense Evasion   | Valid Accounts | T1078 |

## Recommendations
1. Implement and enforce account lockout policy for failed login thresholds.
2. Require Multi-Factor Authentication (MFA) for all privileged and remote accounts.
3. Audit RDP and administrative access to validate legitimate use.
4. Monitor for continued failed logon spikes and create dynamic alerts for Event ID 4625.
5. Restrict RDP exposure to internal networks only.

## 🪞 Reflection
This incident reinforced my understanding of how failed logon patterns can signal early-stage brute-force attacks.
Correlating Event IDs 4625 and 4624 helped confirm that no compromise occurred, while visualizing the data clarified attack timing and scope.
Going forward, I plan to develop automated Sentinel rules and playbooks to detect similar behavior proactively.

## 📂 Repository Layout
```text
📁 Microsoft-30Day-SOC-Challenge/
│
├── README.md                                  ← Main overview + links to each day
│
├── Day1-Lab-Setup-and-Planning/
│   ├── README.md                              ← Azure setup, billing alert, naming convention, lab plan
│   └── screenshots/
│
├── Day2-Virtual-Machine-Setup/
│   ├── README.md                              ← VM creation (Azure/on-prem)
│   └── screenshots/
│
├── Day3-Sentinel-Workspace-Overview/
│   ├── README.md                              ← Description of Sentinel tabs + workspace screenshot
│   └── screenshots/
│
├── Day4-KQL-Queries/
│   ├── README.md                              ← 3 queries + explanation of one
│   ├── queries/                               ← .kql files
│   └── screenshots/
│
├── Day5-Dashboard-Creation/
│   ├── README.md                              ← Dashboard explanation + visual types used
│   └── screenshots/
│
├── Day6-Alert-and-Incident-Creation/
│   ├── README.md                              ← KQL query + analytic rule + screenshot of alert
│   ├── queries/
│   └── screenshots/
│
├── Day7-Incident-Investigation-Report/
│   ├── README.md                              ← Report template + findings + recommendations
│   └── report.md                              ← Full incident report (like Pikachu.exe example)
│
├── Day8-Bookmark-and-Manual-Incident/
│   ├── README.md                              ← Bookmarking & manual incident workflow
│   ├── kql/
│   ├── report.md                              ← 2–3 sentence summary of notable log
│   └── screenshots/
│
└── Resources/
    ├── tools-list.md                          ← Sentinel, Defender, Entra ID, KQL, VirusTotal, etc.
    ├── kql-cheatsheet.md
    ├── official-links.md                      ← Docs + MyDFIR challenge links
    └── portfolio-banner.png                   ← Optional banner image
