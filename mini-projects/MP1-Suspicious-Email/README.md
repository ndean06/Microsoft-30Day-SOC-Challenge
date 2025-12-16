# Mini Project 1 – Suspicious Email Investigation

## Objective
Simulate a phishing email delivery and demonstrate how a SOC analyst investigates sender behavior, delivery metadata, and user interaction using Microsoft Defender for Office and Advanced Hunting.

## Scenario Overview
An invoice-themed phishing email was delivered to multiple users from an external sender. One user interacted with the embedded link, while another did not. This project documents the investigation, scoping, and impact assessment performed by a SOC analyst.

## What’s Included

### Technical Walkthrough  
Step-by-step email investigation with screenshots, Defender Explorer analysis, Advanced Hunting queries, and scoping decisions.

→ [`MP1-Suspicious-Email-Walkthrough`](walkthrough.md)

## Tools Used
- Microsoft Defender for Office 365
- Microsoft Defender XDR (Advanced Hunting)
- Outlook
- KQL

## Outcome

The email was confirmed as a phishing attempt delivered to two users. One user (`jsmith`) clicked the embedded link, while the other (`bsmith`) did not. The destination domain was benign, and no malware execution, endpoint alerts, or identity compromise were observed. The activity was contained at the email layer and required no further escalation beyond remediation and monitoring.

## Screenshots
All screenshots referenced in the walkthrough are stored in the `/screenshots` directory.


