A 30-day journey through real-world SOC workflows using **Microsoft Sentinel**, **Microsoft Defender XDR**, **Defender for Endpoint**, **Defender for Office**, and **EntraID Protection**.

This challenge focused on building hands-on experience with detection, investigation, and incident response across identity, email, and endpoint telemetry.

---

## Overview

This repository documents my completion of the **MyDFIR Microsoft 30-Day SOC Analyst Challenge**, where I designed and operated a cloud-based SOC lab to mirror real Tier 1–Tier 2 SOC workflows.

Over 30 days, I performed real investigations, wrote structured incident reports, ran threat-hunting queries, simulated attacks, and correlated alerts across multiple Microsoft security products.


Key skills practiced:
- Threat hunting with KQL  
- Incident investigation across identity, email, and endpoint  
- Writing structured IR reports  
- Building detections, dashboards, and workflows

---

## Table of Contents
- [Mini Projects](#mini-projects-portfolio-highlights)
- [Repository Structure](#-repository-structure)
- [Suspicious Email Investigation](mini-projects/MP1-Suspicious-Email.md)
- [Cross-Domain Incident Report (PDF)](mini-projects/MP4-Incident-Report.pdf)


---

## Mini Projects (Portfolio Highlights)

### 1. Suspicious Email Investigation
Analysis of a phishing email using Defender for Office, Explorer, and threat intelligence to determine malicious intent and potential credential exposure.

→ Walkthrough:

### 2. Endpoint Compromise Analysis
Investigation of suspicious endpoint activity using Defender for Endpoint telemetry, process execution analysis, and MITRE ATT&CK mapping.

→ Walkthrough:

### 3. Conditional Access & Identity Attack Simulation
Simulation of a foreign login attempt to test Conditional Access enforcement and identity risk detection in Entra ID.

→ Walkthrough: 

---

### 4. Cross-Domain Incident Report – Hands-on Keyboard Attack
End-to-end incident investigation correlating phishing, identity compromise, and hands-on-keyboard endpoint activity using Microsoft Defender XDR and KQL.

- 📘 Walkthrough (evidence, queries, screenshots):  
  → [`mini-projects/MP4-HandsOnKeyboard-Incident-Investigation.md`](mini-projects/MP4-HandsOnKeyboard-Incident-Investigation.md)

- 📄 Formal Incident Report (PDF):  
  → [`mini-projects/MP4-HandsOnKeyboard-Incident-Report.pdf`](mini-projects/MP4-HandsOnKeyboard-Incident-Report.pdf)

---


## 📂 Repository Structure

```text
.
├─ mini-projects/        # Full write-ups of the 4 major projects
├─ days/                 # Daily learning logs and lab notes from the 30-day challenge
├─ queries/              # KQL hunting & detection queries
└─ screenshots/          # Evidence and visuals used in the reports
