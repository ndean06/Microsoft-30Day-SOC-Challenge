# Mini Project 4 – Cross-Domain Incident Report

## Hands-on Keyboard Attack via Credential Misuse

## Objective

Investigate a hands-on-keyboard attack following credential misuse, correlating phishing, identity logs, and endpoint telemetry using Microsoft Defender XDR and KQL.

## Scenario Overview

A user account was compromised and used to perform interactive logons from a foreign location. Post-authentication activity included credential theft attempts, discovery tooling, and a blocked privilege-escalation attempt.

This project documents the full investigation lifecycle, from initial alert to containment and reporting.

## What’s Included

### 📘 Technical Walkthrough

Step-by-step investigation with queries, screenshots, and analyst reasoning.

→ [MP4-HandsOnKeyboard-Incident-Investigation.md](MP4-HandsOnKeyboard-Incident-Investigation.md)

### 📄 Formal Incident Report

SOC-style incident report suitable for leadership or compliance review.

→ [MP4-HandsOnKeyboard-Incident-Report.pdf](MP4-HandsOnKeyboard-Incident-Report.pdf)

## Tools Used

- Microsoft Defender XDR

- Microsoft Defender for Endpoint

- Microsoft Defender for Office 365

- Entra ID Protection

- KQL (Advanced Hunting)

## Screenshots

All supporting screenshots and evidence are stored in the /screenshots directory and referenced throughout the walkthrough.