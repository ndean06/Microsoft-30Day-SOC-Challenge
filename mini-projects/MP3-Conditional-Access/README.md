# Mini Project 3 – Conditional Access & Identity Attack Simulation

## Objective

Simulate a foreign login attempt to evaluate Conditional Access enforcement and identity risk detection using Entra ID Protection.

## Scenario Overview

This project simulates a sign-in from an unexpected geographic location to test how identity protections respond to risky authentication events. The investigation validates alerting, policy enforcement, and visibility into identity-based threats.

The investigation simulates a SOC analyst validating identity-based threats before endpoint compromise occurs.

## Incident Type

Identity Threat – Risky Sign-In / Conditional Access Enforcement

### Technical Walkthrough

Step-by-step identity investigation using Entra ID sign-in logs, Conditional Access evaluation, and risk indicators.

→ [README.md](README.md)

## Investigation Focus

- Risky sign-in detection
- Conditional Access policy enforcement
- Sign-in log analysis (location, IP, device)
- Identity risk vs successful authentication
- Pre-endpoint attack prevention

## Tools Used

- Microsoft Entra ID (Azure AD)
- Conditional Access
- Entra ID Sign-in Logs
- Entra ID Identity Protection
- Microsoft Defender XDR
- Advanced Hunting (KQL)

## Outcome

- The simulated Foreign sign-in activity was detected and initially succeeded but was flagged as high risk. 
- Conditional Access enforcement prevented continued access, and no endpoint compromise was observed.


## Screenshots

All screenshots and evidence from the identity attack simulation are stored in the /screenshots directory.



