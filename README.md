# Microsoft-30Day-SOC-Challenge
A 30-day journey through real-world SOC operations using Microsoft security tools. Includes KQL queries, incident response workflows, and reflections on building modern cloud detections.

## 📘 Overview
This repository documents my journey through the **MyDFIR Microsoft 30-Day SOC Analyst Challenge**, where I built, configured, and analyzed a Microsoft SOC environment using **Sentinel**, **Defender XDR**, and **Entra ID**.


## 📚 Table of Contents
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
_(Will add screenshots and lab diagram later.)_

**Screenshots:**  
_(Add screenshots of Azure portal, billing alert setup, and resource group here.)_


## Day 2 — Virtual Machine Setup

**Objective:**  
Create a virtual machine in Azure or on-premises for use in the SOC lab.

**Tasks Completed:**  
- Deployed Windows 10 VM for endpoint simulation.  
- Configured network settings and baseline security policies.  
- Verified connectivity to Microsoft Sentinel workspace.  

**Reflection (Placeholder):**  
Learned how to spin up and secure virtual machines for monitoring and testing.  
_(Will add VM specs and screenshots later.)_

**Screenshots:**  
_(Add screenshots of VM creation wizard and system overview here.)_


## Day 3 — Sentinel Workspace Overview

**Objective:**  
Explore the Sentinel interface and familiarize with its tabs, features, and capabilities.

**Tasks Completed:**  
- Reviewed **Overview**, **Incidents**, **Logs**, **Hunting**, and **Workbooks** tabs.  
- Captured initial dashboard screenshot for future portfolio use.  

**Reflection (Placeholder):**  
Understanding Sentinel’s UI made it easier to navigate during later assignments.  
_(Will update with Sentinel workspace screenshot.)_

**Screenshots:**  
_(Add Sentinel overview image here.)_

# Day 4 — KQL Queries

## 🎯 Objective
Use KQL to query Microsoft Sentinel logs and identify authentication failures, event trends, and host activity patterns to strengthen detection and analysis capabilities.

---

## 🧰 Tools & Concepts
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

## 🎯 Objective
Add three panels to Microsoft Sentinel dashboard using different visualization types: bar, line, and pie.

---

## 🧰 Tools & Concepts
- Microsoft Sentinel Workbooks  
- KQL Queries for visual data  
- Visualization Types: Bar • Line • Pie  

---

## 🔹 Panel 1 – Failed Logons by Account (Pie Chart)

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
![Panel 1 — Top 5 Failed Logons by Account ](Day5-Dashboard-Creation/screenshots/top-failed-login-pie.png)

### Purpose:
Breaks down the top 5 accounts with the highest number of failed logon events (Event ID 4625).
Visualizing the data as proportions highlighting accounts that contribute most to the failed login volume.
### Why It’s Important:
- Quickly identifies high-risk or frequently attacked accounts.
- Useful for validating whether brute-force activity targets specific privileged users.
- Provides an at-a-glance metric for SOC dashboards or executive summaries.
### Observation:
Administrator-level accounts dominated the failed login attempts (`\ADMINISTRATOR, \admin, \administrator`), suggesting targeted password-guessing activity on privileged users.
This insight guides better alert tuning and reinforces defenses for privileged account credentials.

## 🔹 Panel 2 – Event ID Count (Column Chart)

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

## 🔹 Panel 3 – Failed Logons Over Time (Line Chart)

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

## 🪞 Reflection
This exercise improved my ability to filter and interpret authentication data using KQL.
I learned how to pivot between account-level and host-level data to identify potential attack patterns and brute-force activity.

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
