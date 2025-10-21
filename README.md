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
Run at least three different KQL queries in Microsoft Sentinel, take a screenshot of each query and its results, and explain what the query looks for and why it’s important.

---

## 🧰 Tools & Concepts
- Microsoft Sentinel  
- Log Analytics Workspace  
- KQL (Kusto Query Language)  
- EventID 4625 (Failed Logon Events)  
- SOC Analysis & Detection

---

## 🧪 Query 1 — Top Accounts with Failed Logons
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
### Observation:
Administrator accounts had an unusually high number of failed attempts, indicating potential credential-stuffing activity.

![Query 1 – Top Accounts with Failed Logons](Day4-KQL-Queries/screenshot/ms_30-day_challenge_ss-1.png)



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
