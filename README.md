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
