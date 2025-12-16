# Mini Project 2 – Endpoint Compromise Analysis

## Objective

Investigate suspicious endpoint activity and determine whether observed behavior represents malicious execution, misuse of legitimate tools, or benign activity using Microsoft Defender for Endpoint.

## Scenario Overview

Defender for Endpoint generated alerts indicating suspicious process execution and abnormal behavior on a Windows host. This investigation focused on validating the alert, analyzing execution chains, and determining whether the activity represented a true endpoint compromise.

The project simulates a Tier 1–Tier 2 SOC analyst workflow for endpoint triage and investigation.

## Incident Type

Endpoint Suspicious Activity – Process Execution / Living-off-the-Land Behavior

## What’s Included

### Technical Walkthrough  
Step-by-step endpoint investigation with process trees, command-line analysis, Advanced Hunting queries, and MITRE ATT&CK mapping.

→ walkthrough.md

## Investigation Focus

- Process execution and parent-child relationships
- Command-line analysis and suspicious binaries
- Endpoint telemetry correlation across Defender tables
- MITRE ATT&CK tactic and technique mapping

## Tools Used

- Microsoft Defender for Endpoint
- Microsoft Defender XDR
- Advanced Hunting (KQL)
- MITRE ATT&CK Framework

## Outcome

The investigation determined that the observed endpoint activity was <malicious / suspicious but contained / benign misuse>, with no evidence of persistence, lateral movement, or credential compromise at the time of analysis.

## Screenshots

All screenshots and supporting evidence referenced in this investigation are stored in the `/screenshots` directory.
