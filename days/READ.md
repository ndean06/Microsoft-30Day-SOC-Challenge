\## Microsoft-30Day-SOC-Challenge

A 30-day journey through real-world SOC operations using Microsoft security stack. Includes KQL queries, incident response workflows, and reflections on building modern cloud detections.



\## Overview

This repository documents my completion of the MyDFIR Microsoft 30-Day SOC Analyst Challenge, where I built and operated a cloud-based SOC environment using:

\- Microsoft Sentinel

\- Microsoft Defender XDR

\- Microsoft Defender for Endpoint

\- Entra ID Protection

&nbsp; 

Over 30 days, I performed real investigations, wrote incident reports, ran hunting queries, tested attack simulations, and created dashboards—mirroring what Tier 1 \& Tier 2 SOC analysts do in production environments.



\# Table of Contents



| Day        | Topic                                      | Description                                            |

| ---------- | ------------------------------------------ | ------------------------------------------------------ |

| \*\*Day 1\*\*  | Lab Setup \& Planning                       | Built the SOC lab \& structured investigation workflow. |

| \*\*Day 2\*\*  | Virtual Machine Setup                      | Deployed Windows test VM for Defender onboarding.      |

| \*\*Day 3\*\*  | Sentinel Workspace Overview                | Connected logs \& explored workspace features.          |

| \*\*Day 4\*\*  | KQL Queries                                | Learned core KQL for hunting \& analytics.              |

| \*\*Day 5\*\*  | Dashboard Creation                         | Built custom dashboards for SOC visibility.            |

| \*\*Day 6\*\*  | Alert \& Incident Creation                  | Triggered alerts and analyzed incidents.               |

| \*\*Day 7\*\*  | Incident Investigation Report              | First structured IR report.                            |

| \*\*Day 8\*\*  | Bookmarks \& Manual Incidents               | Documented evidence for investigations.                |

| \*\*Day 9\*\*  | Project Documentation \& Resource Index     | Created resource library + tools list.                 |

| \*\*Day 10\*\* | Device Inventory \& Exposure Management     | MDE exposure analysis.                                 |

| \*\*Day 11\*\* | Defender for Office P2 Overview            | Safe Links, Safe Attachments, Anti-Phishing.           |

| \*\*Day 12\*\* | Safe Links Policy                          | Policy creation \& testing.                             |

| \*\*Day 13\*\* | Anti-Phishing Policy                       | Policy creation \& tuning practice.                     |

| \*\*Day 14\*\* | Explorer \& Quarantine                      | Email investigation using Explorer.                    |

| \*\*Day 15\*\* | Phishing Simulation                        | Ran Office 365 phishing attack test.                   |

| \*\*Day 16\*\* | Suspicious Email Report — \*\*Mini Project\*\* | Full phishing IR report.                               |

| \*\*Day 17\*\* | Defender for Endpoint                      | Telemetry exploration.                                 |

| \*\*Day 18\*\* | MDE Dashboard Analysis                     | Endpoint health \& threat visibility.                   |

| \*\*Day 19\*\* | Intune ASR Rules                           | Hardened Windows endpoint.                             |

| \*\*Day 20\*\* | Atomic Red Team Attack                     | Simulated endpoint compromise.                         |

| \*\*Day 21\*\* | Threat Hunting                             | Wrote structured hunting queries.                      |

| \*\*Day 22\*\* | Hypothesis Testing                         | Query-driven threat hunting.                           |

| \*\*Day 23\*\* | Endpoint Investigation — \*\*Mini Project\*\*  | Full endpoint compromise analysis.                     |

| \*\*Day 24\*\* | Entra ID Protection                        | Identity risk monitoring.                              |

| \*\*Day 25\*\* | Conditional Access (Foreign IP Test)       | Foreign-login simulation \& policy validation.          |

| \*\*Day 26\*\* | Sign-in \& Audit Log Review                 | Identity investigation fundamentals.                   |

| \*\*Day 27\*\* | Entra Logs → Sentinel                      | Data ingestion + log validation.                       |

| \*\*Day 28\*\* | Multi-Signal Simulation                    | Phishing + risky sign-in + MDE threat.                 |

| \*\*Day 29\*\* | Incident Investigation — \*\*Mini Project\*\*  | End-to-end cross-domain incident report.               |





\# Mini-Projects Completed

Highlights of the 30 Day Challenge:



\## Mini Project 1 — Suspicious Email Investigation

\- Analyzed headers, URLs, attachments, and authentication patterns.

\- Used Defender for Office, Explorer, and Threat Intelligence sources.



\## Mini Project 2 — Endpoint Compromise Analysis

\- Reviewed execution, persistence, and network signals.

\- Wrote an end-to-end investigation report with MITRE mapping.



\## Mini Project 3 — Conditional Access + Identity Attack

\- Simulated foreign login attempt and validated policy enforcement.



\## Mini Project 4 — Cross-Domain Incident Report

\- Combined identity logs, endpoint telemetry, process events, and KQL queries.

\- Built a WHO/WHAT/WHEN/WHERE/HOW report detailing attacker actions.





\## Day 1 - Lab Setup and Planning



\*\*Objective:\*\*  

Create an Azure account, set up billing alerts, and define a resource naming convention.  

Plan out the lab structure and goals for the 30-Day Challenge.



\*\*Tasks Completed:\*\*  

\- Created Microsoft Azure account and configured billing alert thresholds.  

\- Defined resource naming convention (e.g., MyDFIR-Dean-Sentinel).  

\- Outlined lab plan and estimated completion schedule.  



\*\*Reflection:\*\*  

Setting up the environment helped me understand Azure cost management and resource organization.  



\## Day 2 - Virtual Machine Setup



\*\*Objective:\*\*  

Create a virtual machine in Azure or on-premises for use in the SOC lab.



\*\*Tasks Completed:\*\*  

\- Deployed Windows 10 VM for endpoint simulation.  

\- Configured network settings and baseline security policies.  

\- Verified connectivity to Microsoft Sentinel workspace.  



\*\*Reflection:\*\*  

Learned how to spin up and secure virtual machines for monitoring and testing.  

&nbsp; 

\## Day 3 - Sentinel Workspace Overview



\*\*Objective:\*\*  

Explore the Sentinel interface and familiarize with its tabs, features, and capabilities.



\*\*Tasks Completed:\*\*  

\- Reviewed \*\*Overview\*\*, \*\*Incidents\*\*, \*\*Logs\*\*, \*\*Hunting\*\*, and \*\*Workbooks\*\* tabs.  

\- Captured initial dashboard screenshot for future portfolio use.  



\*\*Reflection:\*\*  

Understanding Sentinel’s UI made it easier to navigate during later assignments.  

&nbsp;

\# Day 4 - KQL Queries



\## Objective

Use KQL to query Microsoft Sentinel logs and identify authentication failures, event trends, and host activity patterns to strengthen detection and analysis capabilities.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- Log Analytics Workspace  

\- KQL (Kusto Query Language)  

\- EventID 4625 (Failed Logon Events)  

\- SOC Analysis \& Detection



---



\## Query 1 - Top Accounts with Failed Logons

```kql

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize FailedAttempts = count() by Account\_s, AccountType\_s

| top 10 by FailedAttempts desc

```

\### Purpose:

Identify which accounts have the highest number of failed login attempts.

\### Why It’s Important:

This helps detect brute-force or password-spraying attacks targeting user or admin accounts.



!\[Query 1 – Top Accounts with Failed Logons](Day4-KQL-Queries/screenshot/ms\_30-day\_challenge\_ss-1.png)

\### Observation:

Administrator accounts had an unusually high number of failed attempts, indicating potential credential-stuffing activity.



\## Query 2 - Most Common Event IDs (Frequency Analysis)

```

SecurityEvent\_CL

| summarize RandomCount = count() by EventID\_s

| sort by RandomCount desc

```

\### Purpose:

Show which Event IDs are most common in the dataset.

\### Why It’s Important:

Helps analysts understand which event types dominate the log flow, giving context to noise vs. signal.



!\[Query 2 — Most Common Event IDs](Day4-KQL-Queries/screenshot/ms\_30-day\_challenge\_ss-2.png)

\### Observation:

Event ID 4625 (Failed Logons) appeared most frequently, confirming heavy authentication failure activity.





\## Query 3 - Failed Logons by Computer and Account

```

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize FailedAttempts = count() by Computer, Account\_s

| top 5 by FailedAttempts desc

```

\### Purpose:

Correlate failed logon attempts with the computers where they occurred.

\### Why It’s Important:

Reveals which systems are being targeted, supporting scoping and prioritization in investigations.



!\[Query 3 — Failed Logons by Computer and Account](Day4-KQL-Queries/screenshot/ms\_30-day\_challenge\_ss-3.png)

\### Observation:

The SOC-FW-RDP host had the highest failed logons, suggesting external RDP brute-force attempts.



\# Day 5 - Dashboard Creation



\## Objective

Add three panels to Microsoft Sentinel dashboard using different visualization types: bar, line, and pie.



---



\## Tools \& Concepts

\- Microsoft Sentinel Workbooks  

\- KQL Queries for visual data  

\- Visualization Types: Bar • Line • Pie  



---



\## Panel 1 – Failed Logons by Account (Pie Chart)



\*\*Objective:\*\*  

Identify which user accounts are experiencing the most failed login attempts by visualizing their proportion of total failures.



\*\*KQL Query:\*\*

```kql

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize Count = count() by Account\_s

| sort by Count

| take 5

```

\### Purpose:

Breaks down the top 5 accounts with the highest number of failed logon events (Event ID 4625).

Visualizing the data as proportions highlighting accounts that contribute most to the failed login volume.

\### Why It’s Important:

\- Quickly identifies high-risk or frequently attacked accounts.

\- Useful for validating whether brute-force activity targets specific privileged users.

\- Provides an at-a-glance metric for SOC dashboards or executive summaries.



!\[Panel 1 — Top 5 Failed Logons by Account ](Day5-Dashboard-Creation/screenshots/top-failed-login-pie.png)

\### Observation:

Administrator-level accounts dominated the failed login attempts (`\\ADMINISTRATOR, \\admin, \\administrator`), suggesting targeted password-guessing activity on privileged users.

This insight guides better alert tuning and reinforces defenses for privileged account credentials.



\## Panel 2 - Event ID Count (Column Chart)



\*\*Objective:\*\*  

Visualize the frequency of different Windows Event IDs in the dataset to identify which event types occur most often.



\*\*KQL Query:\*\*

```kql

SecurityEvent\_CL

| summarize Total = count() by EventID\_s

| sort by Total asc

| take 15

| render columnchart

```



\### Purpose:

This column chart displays the top 15 Event IDs and their frequency counts from security logs.

By visualizing event frequency, analysts can quickly determine which activities dominate the environment, which helps separate common background noise from potential anomalies.

\### Why It’s Important:

\- Reveals the most frequent system events (normal baseline behavior).

\- Highlights rare or infrequent Event IDs that might indicate suspicious activity.

\- Helps prioritize which logs to focus on for deeper analysis.



!\[Panel 2 — Event ID Count](Day5-Dashboard-Creation/screenshots/event-id-count-bar.png)

\### Observation:

Event ID 5058 occurred the most, significantly higher than others like 4624 and 4625.

Can be used to help establish a baseline for normal system activity.



\## Panel 3 - Failed Logons Over Time (Line Chart)



\*\*Objective:\*\*  

Visualize the trend of failed logon attempts across accounts over a specific time window.



\*\*KQL Query:\*\*

```kql

SecurityEvent\_CL

| extend EventTime = todatetime(replace\_string(TimeCollected\_UTC\_\_s, ",", ""))

| where EventTime between (datetime(2021-04-16 00:00:00) .. datetime(2021-04-17 00:00:00))

| summarize FailedLogons = count() by bin(EventTime, 5m), Account\_s

| order by EventTime asc

| render timechart

```

\### Purpose:

This line chart tracks failed logon activity for each account in 5-minute intervals, helping analysts identify login bursts or anomalies across time.

\### Why It’s Important:

\- Reveals temporal patterns in brute-force or password-spray attempts.

\- Helps correlate spikes in failed logons with specific attack windows.

\- Enables proactive tuning of analytic rules and rate-based detections.

&nbsp; 

!\[Panel 3 — Failed Logons Over Time)](Day5-Dashboard-Creation/screenshots/failed-login-by-min-line.png)

\### Observation:

The `\\ADMINISTRATOR` account maintained consistently high failure counts, peaking around 03:35 AM, indicating repeated login attempts within a short period.

Other accounts like `\\admin` and `\\administrator` show similar spikes, supporting a likely password-spray pattern across multiple privileged users.



\# Day 6 - Alert and Incident Creation



\## Objective

Create a custom analytic rule in Microsoft Sentinel using KQL to detect multiple failed logon attempts and generate an alert when thresholds are exceeded.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- Microsoft Defender XDR  

\- KQL (Kusto Query Language)  

\- Analytic Rules \& Incidents  

\- Detection Engineering  



---



\## Detection Query

```kql

SecurityEvent\_CL 

| where EventID\_s == "4625" 

| summarize FailedLogons = count() by Account\_s

| where FailedLogons >= 1000

```

\### Purpose:

Detect accounts exceeding 1,000 failed logon attempts. A common indicator of brute-force or password-spray activity. 

\### Why It’s Important:

\- Failed logons are early indicators of brute-force or password-spray attacks.

\- Detecting abnormal volumes helps identify unauthorized access attempts.

\- Custom analytic rules in Sentinel enable proactive detection and alerting.

\- Supports MITRE ATT\&CK technique TA0006 – Credential Access.

!\[Alert 1000 — Failed Logons Over Time)](Day6-Alert-Incidents/screenshots/incident-alert.png)

\### Observation:

The rule triggered several MyDFIR-ndean-FailedLogonAlert incidents (9–15 attempts), confirming the query worked.

In a real SOC, this would prompt a check for repeated failures or password-spray activity.



\# Day 7 - Incident Investigation Report



\## Objective

Investigate an alert generated from the “Multiple Failed Logons Detection” rule in Microsoft Sentinel to determine scope, impact, and recommended actions.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- KQL (Query Language)  

\- MITRE ATT\&CK T1110 (Brute Force)  

\- Incident Handling Lifecycle  



---



\## Findings

\*\*Alert Name:\*\* Multiple Failed Logons Detected  

\*\*Severity:\*\* High  

\*\*Event ID:\*\* 4625 (Failed Logon)  

\*\*Time Range:\*\* 2024-04-16 08:34 UTC – 09:33 UTC  

\*\*Affected Hosts:\*\* `SHIR-Hive`, `SHIR-SAP`, `SOC-FW-RDP`  

\*\*Targeted Accounts:\*\* `\\ADMINISTRATOR`, `\\admin`, `\\administrator`  



---



\## Investigation Summary

On 2024-04-16 08:34 UTC, multiple failed logon attempts were detected from several hosts targeting privileged accounts.  

The activity pattern suggested a \*\*brute-force or password-spray attack\*\*.  

No successful logons (Event ID 4624) were observed, indicating the attempts were unsuccessful.  

The activity likely used automated credential guessing via RDP or network authentication.



---



\##  WHO

\*\*Hosts:\*\* `SHIR-Hive`, `SHIR-SAP`, `SOC-FW-RDP`  

\*\*Accounts Targeted:\*\* Administrator accounts across multiple hosts  



!\[Host Activity](Day7-Incident-Investigation-Report/screenshots/ms-30Day\_Challenge-7-1.png)



!\[Accounts Targeted](Day7-Incident-Investigation-Report/screenshots/ms-30Day\_Challenge-7-2.png)



---



\## WHAT

Failed attempts totaling \*\*18,163\*\* across the three hosts.



---



\## WHEN

| Host | Time Range (UTC) |

|------|-------------------|

| SHIR-Hive | 2021-04-16 08:34 – 09:33 |

| SHIR-SAP | 2021-04-16 08:34 – 09:33 |

| SOC-FW-RDP | 2021-04-16 08:34 – 09:00 |



!\[Timeline Evidence](screenshots/when\_activity.png)



Limited data to confirm if activity continued beyond this window.



---



\## WHERE

Activity originated from internal hosts `SHIR-Hive`, `SHIR-SAP`, and `SOC-FW-RDP`,  

suggesting an attack via RDP or Windows authentication services.



---



\## WHY

Likely an automated attacker attempting to gain access to privileged accounts via brute-force or password spray.  

If these hosts are internet-facing or relay services, external actors may be involved.



---



\## HOW

Automated tool or script iterating credentials against accounts over RDP / domain authentication.  

The hostname `SOC-FW-RDP` indicates a remote desktop front end likely used for testing or management.



---



\## Supporting KQL Queries

```kql

// Failed logons by host

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize FailedAttempts = count() by Computer, Account\_s

| top 10 by FailedAttempts desc

```



\# Day 8 - Bookmark \& Manual Incident



\## Objective

Use Microsoft Sentinel to identify a notable pattern in Office 365 activity logs, bookmark the finding, and create a manual incident for further investigation.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- OfficeActivity\_CL table  

\- KQL (Kusto Query Language)  

\- Bookmarks \& Manual Incidents  

\- SOC Investigation Workflow  



---



\## KQL Query

```kql

OfficeActivity\_CL

| where Operation\_s == "FileAccessed"

```

\### Purpose:

Retrieve Office 365 file-access events to review for unusual activity such as access from new or unexpected IP addresses.

\### Why It's Important:

Manual incidents help analysts capture context that automated detections may miss.

They demonstrate the ability to:

\- Recognize suspicious behavior during proactive log review

\- Escalate findings with supporting evidence

\- Maintain clear documentation for peer validation

!\[Bookmark Abnormal IP)](Day8-Bookmark-and-Manual-Incident/screenshots/ms\_30-day\_challenge-bookmark.png)

\### Observation:

\- The FileAccessed query showed activity from an unusual IP address.

\- A bookmark was created for further review.

\- May indicate suspicious or unauthorized access requiring investigation.



\## MITRE ATT\&CK Mapping

| Tactic            | Technique      | ID    |

| ----------------- | -------------- | ----- |

| Credential Access | Brute Force    | T1110 |

| Execution         | User Execution | T1204 |

| Defense Evasion   | Valid Accounts | T1078 |



\## Recommendations

1\. Implement and enforce account lockout policy for failed login thresholds.

2\. Require Multi-Factor Authentication (MFA) for all privileged and remote accounts.

3\. Audit RDP and administrative access to validate legitimate use.

4\. Monitor for continued failed logon spikes and create dynamic alerts for Event ID 4625.

5\. Restrict RDP exposure to internal networks only.



\## 🪞 Reflection

This incident reinforced my understanding of how failed logon patterns can signal early-stage brute-force attacks.

Correlating Event IDs 4625 and 4624 helped confirm that no compromise occurred, while visualizing the data clarified attack timing and scope.

Going forward, I plan to develop automated Sentinel rules and playbooks to detect similar behavior proactively.





\# Day 29 - Microsoft Defender XDR Incident Report



\*\*Alert:\*\* Hands-on Keyboard Attack via Possible Credential Misuse



\*\*Serverity:\*\* High



!\[XDR-Incident](Day29-Final-Mini-Project/xdr-incident.png)

\*Figure 1 - Microsoft Defender XDR incident overview showing high-severity alerts.\*





\## 1. Findings



\### Title:  

Hands-on Keyboard Activity via Possible Credential Misuse



\### Timeframes:

\- First Malicious Activity: 2025-11-22 05:55 UTC

\- Second Activity Wave: 2025-11-24 05:12–05:29 UTC



\### Host

\- mydfir-ndean-vm



\### IOC Domain

\- None observed before compromise



\### IOC IPs

\- 45.76.129.144 (foreign IP, London UK — impossible travel indicator)

\- 76.31.117.80 (expected region, initial login source)



\### Possible Malware / Tooling

\- HackTool:Win32/Mimikatz

\- HackTool:Win32/Mimikatz!pz

\- HackTool:Win32/Mimikatz!MSR

\- Trojan:PowerShell/Mimikatz.A

\- SOAPHound

\- AdFind

\- BadPotato





!\[Initial Mimikatz Detection](Day29-Final-Mini-Project/Intial-mimikatz-detection.png) 

\*Figure 2 - Initial Mimikatz credential-theft detection on the compromised host.\*



\## 2. Investigation Summary



Between November 22, 2025 at 11:55 UTC and November 24, 2025 at 11:29 UTC, Microsoft Defender XDR observed malicious activity on mydfir-ndean-vm tied to the account AzureAD\\JennySmith (jsmith). The incident began immediately after successful RemoteInteractive logins from two geographically inconsistent IP addresses, indicating likely credential misuse.



The first wave (starting Nov 22, 11:55 UTC) involved Mimikatz execution, interactive PowerShell activity, and initial domain discovery. The second wave (from Nov 24, 11:12–11:29 UTC) included continued credential-theft attempts, expanded AD reconnaissance using AdFind and SOAPHound, and a blocked privilege-escalation attempt with BadPotato.



Defender blocked or remediated all malicious activity. No successful privilege escalation, lateral movement, or data exfiltration occurred, and activity remained contained to mydfir-ndean-vm.



\## 3. Cross-Domain Correlation (Email → Identity → Endpoint)



\### 3.1 Email – Phishing Attempt (Initial Vector)





!\[Phishing Email](Day29-MiniProject-IncidentInvestigation/screenshots/phishing-email-sent.png)

\*Figure 3 - Phishing email providing the likely initial credential exposure point.\*



\- User received a phishing email containing a suspicious link

\- Defender for Office logged the message and performed Safe Links scanning

\- No confirmed click event, but email provides a credible source for credential exposure



\#### Email → Identity Connection:

Phishing email precedes risky sign-in — indicating possible credential compromise.



\### 3.2 Identity – Risky Sign-in / Impossible Travel



\#### Risky Sign-In Query - Identify Risky Sign-in From a Foreign IP



```kql

// Risky Sign-In (Foreign Location / Impossible Travel)

DeviceLogonEvents

| where DeviceName == "mydfir-ndean-vm"

| where LogonType contains "RemoteInteractive" or LogonType contains "Network"

| where RemoteIP != "76.31.117.80"   // expected region IP

| project Timestamp, AccountName, LogonType, RemoteIP, ActionType

| order by Timestamp asc

```



\##### What this query does:



\- Filters to interactive or network logons on the victim VM

\- Excludes your known “home region” IP to surface foreign activity

\- Shows only successful RemoteInteractive logons from unexpected IPs

\- Helps confirm credential misuse from 45.76.129.144





!\[Risky Signin](Day29-MiniProject-IncidentInvestigation/screenshots/risky-signin.png)



\*Figure 4.1 - Successful foreign RemoteInteractive logons from 45.76.129.144 indicating credential misuse and potential impossible travel.\*



\#### Impossible Travel Query - Detect “Impossible Travel” Between Logons



```kql

//Impossible Travel

DeviceLogonEvents

| where DeviceName == "mydfir-ndean-vm"

| where AccountName == "jsmith"

| order by Timestamp asc

| extend NextTime = next(Timestamp), NextIP = next(RemoteIP)

| extend DiffMinutes = datetime\_diff("minute", NextTime, Timestamp)

| where RemoteIP != NextIP and DiffMinutes <= 60

| project Timestamp, AccountName, DeviceName, RemoteIP, NextIP, DiffMinutes

```



\##### What this query does:



\- Sorts all sign-ins for the compromised account

\- Compares each login with the next login (timestamp + IP)

\- Calculates time between the two logons

\- Flags cases where:

&nbsp;	- IP changes location, AND

&nbsp;	- The time between logons is too short to travel physically

\- This helps strengthen the case of impossible travel and strongly supports credential compromise





!\[Impossible Travel](Day29-MiniProject-IncidentInvestigation/screenshots/Impossible-Travel1.png)



\*Figure 4.2 — Impossible Travel event showing rapid IP change from expected region (76.31.117.80) to foreign IP (45.76.129.144).\*



\##### Why this matters

\- Two sign-ins happen back-to-back from geographically incompatible IPs

\- Entra ID flags the event as Impossible Travel

\- The login succeeds, which means credentials were valid

\- This ties directly back to the phishing email earlier in the chain



\##### Identity → Endpoint Connection:

Minutes after the foreign login, hands-on-keyboard activity attacker appear on the endpoint, signaling a progression from identity compromise to endpoint compromise.



\### 3.3 Endpoint – Hands-on Keyboard Attack Activity



\#### Attacker Timeline Query



```kql

//Attacker Timeline

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   EventTable,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   AccountSid,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   InitiatingProcessAccountSid,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   InitiatingProcessCommandLine,

&nbsp;   EffectiveFolderPath,

&nbsp;   ProcessRemoteSessionIP,

&nbsp;   InitiatingProcessRemoteSessionIP

```





\##### What this query does:



\- Builds a unified attacker timeline by unioning multiple Microsoft Defender tables

\- Filters activity to \*\*mydfir-ndean-vm\*\* to look at activity from the system the attacker actually touched.

\- Anchor the timeline to the known time of compromise \*\*Timestamp > datetime(2025-11-22T11:48:53.8720476Z)\*\*

\- Tracks hands-on-keyboard activity from the attacker by isolating actions tied to that session 

\- Normalize file/process paths with \*\*EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)\*\*, giving me a single folder path even though different tables store it in different columns.





!\[Attacker Timeline](Day29-MiniProject-IncidentInvestigation/screenshots/Attacker-Timeline.png)



\*Figure 5 — Attacker session timeline showing interactive commands and processes executed directly after initial access.\*





Minutes after risky sign-in, endpoint logs show post-authentication activity executions 



\- Ran Mimikatz for credential harvesting

\- Conducted interactive PowerShell sessions

\- Performed Active Directory discovery using AdFind

\- Attempted privilege escalation via BadPotato.exe

\- No evidence of BadCastle enumeration

\- Attempted RDP lateral movement, which was blocked

\- Attacker transitioned from identity compromise to full endpoint exploitation attempt.



\#### Mimikatz Variants



```kql

// Mimikatz variants

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "mimi"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   EffectiveFolderPath

```



!\[Mimikatz Variants](Day29-MiniProject-IncidentInvestigation/screenshots/mimikatz-variants.png)



\*Figure 6 — Mimikatz components created and executed in rapid succession, showing hands-on-keyboard credential-theft activity immediately following the attacker’s remote logon.\*



\#### Interactive PowerShell



```kql

//Interactive PowerShell

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "powershell"

or EffectiveFolderPath contains "pwsh"

and ProcessCommandLine !has "-File"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   InitiatingProcessCommandLine,

&nbsp;   EffectiveFolderPat

```



!\[Interactive PowerShell](Day29-MiniProject-IncidentInvestigation/screenshots/Interactive-Powershell.png)



\*Figure 7 — Early attacker activity showing PowerShell execution, browser launch, named pipe usage, and repeated memory manipulation events (NtProtectVirtualMemory) occurring immediately after the foreign interactive logon, indicating hands-on-keyboard post-compromise actions.\*



\#### Discovery tools



```kql

// Discovery tools - AdFind 

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "adf"

or EffectiveFolderPath contains "adfind"

or ProcessCommandLine contains "adf"

or AdditionalFields contains "adf"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   EffectiveFolderPath

```



!\[Discovery Tools](Day29-MiniProject-IncidentInvestigation/screenshots/adfind.png)



\*Figure 8 — Second activity wave showing AdFind and SOAPHound execution via PowerShell, followed by AV detections and file changes indicating renewed discovery attempts.\*



\#### Privilege Escalation 



```kql

//privilege escalation - Bad Potato

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "bad"

or ProcessCommandLine contains "bad"

or AdditionalFields contains "bad"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   EffectiveFolderPath

```



!\[Privilege Escalation](Day29-MiniProject-IncidentInvestigation/screenshots/badpotato.png)



\*Figure 9 — BadPotato privilege-escalation attempts detected and blocked, followed by related file modifications during the second activity wave.\*



\## 4. WHO / WHAT / WHEN / WHERE / WHY / HOW



\### WHO



\- Activity tied to the compromised account AzureAD\\JennySmith (jsmith / jennysmith).

\- The activity is tied to the compromised user account AzureAD\\JennySmith (jsmith).

\- The attacker authenticated using valid credentials from a foreign IP (45.76.129.144) not associated with the legitimate user.

\- All hands-on-keyboard actions were executed under this identity after the unauthorized login.



\### WHAT



\- The attacker performed credential theft (Mimikatz variants), AD discovery (AdFind, SOAPHound), and privilege-escalation attempts (BadPotato).

\- Multiple malicious files were created and executed, all originating from PowerShell sessions.

\- Defender detected and blocked these actions, preventing further escalation or lateral movement.



\### WHEN



Identifies when the attacker activity occurred and how events progressed over time.

Key Timestamps:

\- Foreign login: November 22, 11:48 UTC

\- First Activity Wave: November 22, 12:55 UTC

\- Blocked RDP lateral movement: 13:10 UTC

\- Second Activity Wave: Nov 24, 11:12–11:29 UTC

\- No malicious activity after 11:48 UTC, Nov 24



Put Screenshot HERE: 

!\[Associated Processes](Day29-Final-Mini-Project/associated-processes.png)

\*Figure 7 — Correlated processes executed under the compromised account during the attacker session.\*



\- Timeline shows activity beginning shortly after the foreign RemoteInteractive logon

\- Attacker actions appear in multiple event sources (DeviceProcessEvents, DeviceEvents, DeviceLogonEvents, DeviceNetworkEvents)

\- Events labeled "Likely attacker" confirm correlation across logons, processes, named pipes, and DPAPI access

\- Process execution under jennysmith occurs minutes after the initial compromise, showing rapid post-logon activity



The sequence reflects a continuous attacker session, with actions increasing in frequency over the identified timeframe



\### WHERE



\- All malicious activity occurred on host mydfir-ndean-vm.

\- Actions originated through RemoteInteractive logons, followed by execution under powershell.exe.

\- EffectiveFolderPath values show payloads placed and executed from:



&nbsp;	- `C:\\Users\\JennySmith\\AppData\\...`

&nbsp;	- `C:\\AtomicRedTeam\\tmp\\...`

&nbsp;	- `C:\\Windows\\System32\\WindowsPowerShell\\...`



\### WHY



\- The attacker’s likely objectives were:

&nbsp;	- Steal credentials for privilege escalation or lateral movement

&nbsp;	- Enumerate the environment to identify valuable targets

&nbsp;	- Attempt local privilege escalation via BadPotato

\- These activities align with early-stage intrusion behavior following credential compromise.



\### HOW



\- The compromise likely began with credential phishing, evidenced by a suspicious email received prior to the foreign login.

\- The attacker authenticated with valid credentials from an unexpected location (“impossible travel”).

\- After logging in, the attacker:

&nbsp;	- Launched PowerShell interactively

&nbsp;	- Loaded Mimikatz components to harvest credentials

&nbsp;	- Used discovery tools (AdFind, SOAPHound)

&nbsp;	- Attempted privilege escalation with BadPotato

\- Defender blocked these efforts before lateral movement or domain compromise occurred.





\## 5. Investigation Timeline Highlight



| Date              | Time (UTC)        | Event Description                                                                 |

|-------------------|-------------------|-----------------------------------------------------------------------------------|

| \*\*Nov 22, 2025\*\*  | 11:12             | Remote logon from \*\*76.31.117.80\*\* (expected region)                              |

|                   | 11:48             | Foreign logon from \*\*45.76.129.144\*\* → \*Impossible travel detected\*               |

|                   | 11:54             | First \*\*Mimikatz\*\* detection                                                      |

|                   | 11:55             | Hands-on-keyboard activity begins (interactive PowerShell)                        |

|                   | 11:57–12:02       | \*\*Credential theft attempts\*\* — Mimikatz components created/executed              |

| \*\*Nov 24, 2025\*\*  | 11:11             | Suspicious PowerShell activity begins                                             |

|                   | 11:18–11:28       | Multiple \*\*Mimikatz\*\* variants detected                                           |

|                   | 11:25–11:28       | \*\*Discovery \& Recon tools executed\*\*: AdFind, whoami, SOAPHound                   |

|                   | 11:25             | \*\*Privilege escalation attempt\*\* using `BadPotato.exe` (blocked)                  |

|                   | 11:27             | Ransomware-linked behavior alert triggered                                        |

|                   | 11:48             | No further malicious activity recorded                                            |







\## 6. Recommendations





\### Enforce MFA and Strengthen Identity Protections

&nbsp;	- Require MFA for all users

&nbsp;	- Enable Entra ID “Risky Sign-ins” and “Risky Users”



\### Harden Endpoint Configurations and Limit Post-Exploitation Tooling

&nbsp;	- Deploy endpoint EDR prevention policies that stop known tools

&nbsp;	- Ensure PowerShell logging is enabled for traceability



\### Apply Least Privilege and Review User Access

&nbsp;	- Audit privileged groups regularly	

&nbsp;	- Restrict ability to run PowerShell for non-administrative users where feasible



\### Endpoint Actions

&nbsp;	- Consider isolating or re-imaging mydfir-ndean-vm

&nbsp;	- Review RDP exposure and harden remote access

&nbsp;	- Validate firewall and remote access policies



\### Conduct User Security Awareness and Phishing Training

&nbsp;	- Link hygiene and credential theft indicators

&nbsp;	- Run simulated phishing campaigns to reinforce behavior





\## 7. Conclusion



Based on the available data, the activity observed on mydfir-ndean-vm appears confined to early-stage intrusion behaviors involving credential misuse, reconnaissance, and attempted execution of credential-theft tools. All malicious tooling appears to have been blocked or remediated by Microsoft Defender, and no evidence was identified showing further spread, persistence, or data compromise.



This incident began with a compromised user account `jsmith/jennysmith` on `mydfir-ndean-vm`, leading to unauthorized remote access from a foreign IP. Once connected, the attacker attempted credential theft using multiple Mimikatz variants, conducted discovery with AdFind and SOAPHound, and attempted privilege escalation through BadPotato. Defender intercepted each phase of the attack chain, preventing the attacker from gaining elevated privileges or moving laterally within the environment.



No sensitive data was accessed, no persistence mechanisms were established, and no signs of ransomware deployment or exfiltration were observed. The activity was fully contained on mydfir-ndean-vm, and the attack was effectively neutralized before achieving its objectives.

&nbsp;Microsoft-30Day-SOC-Challenge

A 30-day journey through real-world SOC operations using Microsoft security stack. Includes KQL queries, incident response workflows, and reflections on building modern cloud detections.



\## Overview

This repository documents my completion of the MyDFIR Microsoft 30-Day SOC Analyst Challenge, where I built and operated a cloud-based SOC environment using:

\- Microsoft Sentinel

\- Microsoft Defender XDR

\- Microsoft Defender for Endpoint

\- Entra ID Protection

&nbsp; 

Over 30 days, I performed real investigations, wrote incident reports, ran hunting queries, tested attack simulations, and created dashboards—mirroring what Tier 1 \& Tier 2 SOC analysts do in production environments.



\# Table of Contents



| Day        | Topic                                      | Description                                            |

| ---------- | ------------------------------------------ | ------------------------------------------------------ |

| \*\*Day 1\*\*  | Lab Setup \& Planning                       | Built the SOC lab \& structured investigation workflow. |

| \*\*Day 2\*\*  | Virtual Machine Setup                      | Deployed Windows test VM for Defender onboarding.      |

| \*\*Day 3\*\*  | Sentinel Workspace Overview                | Connected logs \& explored workspace features.          |

| \*\*Day 4\*\*  | KQL Queries                                | Learned core KQL for hunting \& analytics.              |

| \*\*Day 5\*\*  | Dashboard Creation                         | Built custom dashboards for SOC visibility.            |

| \*\*Day 6\*\*  | Alert \& Incident Creation                  | Triggered alerts and analyzed incidents.               |

| \*\*Day 7\*\*  | Incident Investigation Report              | First structured IR report.                            |

| \*\*Day 8\*\*  | Bookmarks \& Manual Incidents               | Documented evidence for investigations.                |

| \*\*Day 9\*\*  | Project Documentation \& Resource Index     | Created resource library + tools list.                 |

| \*\*Day 10\*\* | Device Inventory \& Exposure Management     | MDE exposure analysis.                                 |

| \*\*Day 11\*\* | Defender for Office P2 Overview            | Safe Links, Safe Attachments, Anti-Phishing.           |

| \*\*Day 12\*\* | Safe Links Policy                          | Policy creation \& testing.                             |

| \*\*Day 13\*\* | Anti-Phishing Policy                       | Policy creation \& tuning practice.                     |

| \*\*Day 14\*\* | Explorer \& Quarantine                      | Email investigation using Explorer.                    |

| \*\*Day 15\*\* | Phishing Simulation                        | Ran Office 365 phishing attack test.                   |

| \*\*Day 16\*\* | Suspicious Email Report — \*\*Mini Project\*\* | Full phishing IR report.                               |

| \*\*Day 17\*\* | Defender for Endpoint                      | Telemetry exploration.                                 |

| \*\*Day 18\*\* | MDE Dashboard Analysis                     | Endpoint health \& threat visibility.                   |

| \*\*Day 19\*\* | Intune ASR Rules                           | Hardened Windows endpoint.                             |

| \*\*Day 20\*\* | Atomic Red Team Attack                     | Simulated endpoint compromise.                         |

| \*\*Day 21\*\* | Threat Hunting                             | Wrote structured hunting queries.                      |

| \*\*Day 22\*\* | Hypothesis Testing                         | Query-driven threat hunting.                           |

| \*\*Day 23\*\* | Endpoint Investigation — \*\*Mini Project\*\*  | Full endpoint compromise analysis.                     |

| \*\*Day 24\*\* | Entra ID Protection                        | Identity risk monitoring.                              |

| \*\*Day 25\*\* | Conditional Access (Foreign IP Test)       | Foreign-login simulation \& policy validation.          |

| \*\*Day 26\*\* | Sign-in \& Audit Log Review                 | Identity investigation fundamentals.                   |

| \*\*Day 27\*\* | Entra Logs → Sentinel                      | Data ingestion + log validation.                       |

| \*\*Day 28\*\* | Multi-Signal Simulation                    | Phishing + risky sign-in + MDE threat.                 |

| \*\*Day 29\*\* | Incident Investigation — \*\*Mini Project\*\*  | End-to-end cross-domain incident report.               |





\# Mini-Projects Completed

Highlights of the 30 Day Challenge:



\## Mini Project 1 — Suspicious Email Investigation

\- Analyzed headers, URLs, attachments, and authentication patterns.

\- Used Defender for Office, Explorer, and Threat Intelligence sources.



\## Mini Project 2 — Endpoint Compromise Analysis

\- Reviewed execution, persistence, and network signals.

\- Wrote an end-to-end investigation report with MITRE mapping.



\## Mini Project 3 — Conditional Access + Identity Attack

\- Simulated foreign login attempt and validated policy enforcement.



\## Mini Project 4 — Cross-Domain Incident Report

\- Combined identity logs, endpoint telemetry, process events, and KQL queries.

\- Built a WHO/WHAT/WHEN/WHERE/HOW report detailing attacker actions.





\## Day 1 - Lab Setup and Planning



\*\*Objective:\*\*  

Create an Azure account, set up billing alerts, and define a resource naming convention.  

Plan out the lab structure and goals for the 30-Day Challenge.



\*\*Tasks Completed:\*\*  

\- Created Microsoft Azure account and configured billing alert thresholds.  

\- Defined resource naming convention (e.g., MyDFIR-Dean-Sentinel).  

\- Outlined lab plan and estimated completion schedule.  



\*\*Reflection:\*\*  

Setting up the environment helped me understand Azure cost management and resource organization.  



\## Day 2 - Virtual Machine Setup



\*\*Objective:\*\*  

Create a virtual machine in Azure or on-premises for use in the SOC lab.



\*\*Tasks Completed:\*\*  

\- Deployed Windows 10 VM for endpoint simulation.  

\- Configured network settings and baseline security policies.  

\- Verified connectivity to Microsoft Sentinel workspace.  



\*\*Reflection:\*\*  

Learned how to spin up and secure virtual machines for monitoring and testing.  

&nbsp; 

\## Day 3 - Sentinel Workspace Overview



\*\*Objective:\*\*  

Explore the Sentinel interface and familiarize with its tabs, features, and capabilities.



\*\*Tasks Completed:\*\*  

\- Reviewed \*\*Overview\*\*, \*\*Incidents\*\*, \*\*Logs\*\*, \*\*Hunting\*\*, and \*\*Workbooks\*\* tabs.  

\- Captured initial dashboard screenshot for future portfolio use.  



\*\*Reflection:\*\*  

Understanding Sentinel’s UI made it easier to navigate during later assignments.  

&nbsp;

\# Day 4 - KQL Queries



\## Objective

Use KQL to query Microsoft Sentinel logs and identify authentication failures, event trends, and host activity patterns to strengthen detection and analysis capabilities.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- Log Analytics Workspace  

\- KQL (Kusto Query Language)  

\- EventID 4625 (Failed Logon Events)  

\- SOC Analysis \& Detection



---



\## Query 1 - Top Accounts with Failed Logons

```kql

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize FailedAttempts = count() by Account\_s, AccountType\_s

| top 10 by FailedAttempts desc

```

\### Purpose:

Identify which accounts have the highest number of failed login attempts.

\### Why It’s Important:

This helps detect brute-force or password-spraying attacks targeting user or admin accounts.



!\[Query 1 – Top Accounts with Failed Logons](Day4-KQL-Queries/screenshot/ms\_30-day\_challenge\_ss-1.png)

\### Observation:

Administrator accounts had an unusually high number of failed attempts, indicating potential credential-stuffing activity.



\## Query 2 - Most Common Event IDs (Frequency Analysis)

```

SecurityEvent\_CL

| summarize RandomCount = count() by EventID\_s

| sort by RandomCount desc

```

\### Purpose:

Show which Event IDs are most common in the dataset.

\### Why It’s Important:

Helps analysts understand which event types dominate the log flow, giving context to noise vs. signal.



!\[Query 2 — Most Common Event IDs](Day4-KQL-Queries/screenshot/ms\_30-day\_challenge\_ss-2.png)

\### Observation:

Event ID 4625 (Failed Logons) appeared most frequently, confirming heavy authentication failure activity.





\## Query 3 - Failed Logons by Computer and Account

```

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize FailedAttempts = count() by Computer, Account\_s

| top 5 by FailedAttempts desc

```

\### Purpose:

Correlate failed logon attempts with the computers where they occurred.

\### Why It’s Important:

Reveals which systems are being targeted, supporting scoping and prioritization in investigations.



!\[Query 3 — Failed Logons by Computer and Account](Day4-KQL-Queries/screenshot/ms\_30-day\_challenge\_ss-3.png)

\### Observation:

The SOC-FW-RDP host had the highest failed logons, suggesting external RDP brute-force attempts.



\# Day 5 - Dashboard Creation



\## Objective

Add three panels to Microsoft Sentinel dashboard using different visualization types: bar, line, and pie.



---



\## Tools \& Concepts

\- Microsoft Sentinel Workbooks  

\- KQL Queries for visual data  

\- Visualization Types: Bar • Line • Pie  



---



\## Panel 1 – Failed Logons by Account (Pie Chart)



\*\*Objective:\*\*  

Identify which user accounts are experiencing the most failed login attempts by visualizing their proportion of total failures.



\*\*KQL Query:\*\*

```kql

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize Count = count() by Account\_s

| sort by Count

| take 5

```

\### Purpose:

Breaks down the top 5 accounts with the highest number of failed logon events (Event ID 4625).

Visualizing the data as proportions highlighting accounts that contribute most to the failed login volume.

\### Why It’s Important:

\- Quickly identifies high-risk or frequently attacked accounts.

\- Useful for validating whether brute-force activity targets specific privileged users.

\- Provides an at-a-glance metric for SOC dashboards or executive summaries.



!\[Panel 1 — Top 5 Failed Logons by Account ](Day5-Dashboard-Creation/screenshots/top-failed-login-pie.png)

\### Observation:

Administrator-level accounts dominated the failed login attempts (`\\ADMINISTRATOR, \\admin, \\administrator`), suggesting targeted password-guessing activity on privileged users.

This insight guides better alert tuning and reinforces defenses for privileged account credentials.



\## Panel 2 - Event ID Count (Column Chart)



\*\*Objective:\*\*  

Visualize the frequency of different Windows Event IDs in the dataset to identify which event types occur most often.



\*\*KQL Query:\*\*

```kql

SecurityEvent\_CL

| summarize Total = count() by EventID\_s

| sort by Total asc

| take 15

| render columnchart

```



\### Purpose:

This column chart displays the top 15 Event IDs and their frequency counts from security logs.

By visualizing event frequency, analysts can quickly determine which activities dominate the environment, which helps separate common background noise from potential anomalies.

\### Why It’s Important:

\- Reveals the most frequent system events (normal baseline behavior).

\- Highlights rare or infrequent Event IDs that might indicate suspicious activity.

\- Helps prioritize which logs to focus on for deeper analysis.



!\[Panel 2 — Event ID Count](Day5-Dashboard-Creation/screenshots/event-id-count-bar.png)

\### Observation:

Event ID 5058 occurred the most, significantly higher than others like 4624 and 4625.

Can be used to help establish a baseline for normal system activity.



\## Panel 3 - Failed Logons Over Time (Line Chart)



\*\*Objective:\*\*  

Visualize the trend of failed logon attempts across accounts over a specific time window.



\*\*KQL Query:\*\*

```kql

SecurityEvent\_CL

| extend EventTime = todatetime(replace\_string(TimeCollected\_UTC\_\_s, ",", ""))

| where EventTime between (datetime(2021-04-16 00:00:00) .. datetime(2021-04-17 00:00:00))

| summarize FailedLogons = count() by bin(EventTime, 5m), Account\_s

| order by EventTime asc

| render timechart

```

\### Purpose:

This line chart tracks failed logon activity for each account in 5-minute intervals, helping analysts identify login bursts or anomalies across time.

\### Why It’s Important:

\- Reveals temporal patterns in brute-force or password-spray attempts.

\- Helps correlate spikes in failed logons with specific attack windows.

\- Enables proactive tuning of analytic rules and rate-based detections.

&nbsp; 

!\[Panel 3 — Failed Logons Over Time)](Day5-Dashboard-Creation/screenshots/failed-login-by-min-line.png)

\### Observation:

The `\\ADMINISTRATOR` account maintained consistently high failure counts, peaking around 03:35 AM, indicating repeated login attempts within a short period.

Other accounts like `\\admin` and `\\administrator` show similar spikes, supporting a likely password-spray pattern across multiple privileged users.



\# Day 6 - Alert and Incident Creation



\## Objective

Create a custom analytic rule in Microsoft Sentinel using KQL to detect multiple failed logon attempts and generate an alert when thresholds are exceeded.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- Microsoft Defender XDR  

\- KQL (Kusto Query Language)  

\- Analytic Rules \& Incidents  

\- Detection Engineering  



---



\## Detection Query

```kql

SecurityEvent\_CL 

| where EventID\_s == "4625" 

| summarize FailedLogons = count() by Account\_s

| where FailedLogons >= 1000

```

\### Purpose:

Detect accounts exceeding 1,000 failed logon attempts. A common indicator of brute-force or password-spray activity. 

\### Why It’s Important:

\- Failed logons are early indicators of brute-force or password-spray attacks.

\- Detecting abnormal volumes helps identify unauthorized access attempts.

\- Custom analytic rules in Sentinel enable proactive detection and alerting.

\- Supports MITRE ATT\&CK technique TA0006 – Credential Access.

!\[Alert 1000 — Failed Logons Over Time)](Day6-Alert-Incidents/screenshots/incident-alert.png)

\### Observation:

The rule triggered several MyDFIR-ndean-FailedLogonAlert incidents (9–15 attempts), confirming the query worked.

In a real SOC, this would prompt a check for repeated failures or password-spray activity.



\# Day 7 - Incident Investigation Report



\## Objective

Investigate an alert generated from the “Multiple Failed Logons Detection” rule in Microsoft Sentinel to determine scope, impact, and recommended actions.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- KQL (Query Language)  

\- MITRE ATT\&CK T1110 (Brute Force)  

\- Incident Handling Lifecycle  



---



\## Findings

\*\*Alert Name:\*\* Multiple Failed Logons Detected  

\*\*Severity:\*\* High  

\*\*Event ID:\*\* 4625 (Failed Logon)  

\*\*Time Range:\*\* 2024-04-16 08:34 UTC – 09:33 UTC  

\*\*Affected Hosts:\*\* `SHIR-Hive`, `SHIR-SAP`, `SOC-FW-RDP`  

\*\*Targeted Accounts:\*\* `\\ADMINISTRATOR`, `\\admin`, `\\administrator`  



---



\## Investigation Summary

On 2024-04-16 08:34 UTC, multiple failed logon attempts were detected from several hosts targeting privileged accounts.  

The activity pattern suggested a \*\*brute-force or password-spray attack\*\*.  

No successful logons (Event ID 4624) were observed, indicating the attempts were unsuccessful.  

The activity likely used automated credential guessing via RDP or network authentication.



---



\##  WHO

\*\*Hosts:\*\* `SHIR-Hive`, `SHIR-SAP`, `SOC-FW-RDP`  

\*\*Accounts Targeted:\*\* Administrator accounts across multiple hosts  



!\[Host Activity](Day7-Incident-Investigation-Report/screenshots/ms-30Day\_Challenge-7-1.png)



!\[Accounts Targeted](Day7-Incident-Investigation-Report/screenshots/ms-30Day\_Challenge-7-2.png)



---



\## WHAT

Failed attempts totaling \*\*18,163\*\* across the three hosts.



---



\## WHEN

| Host | Time Range (UTC) |

|------|-------------------|

| SHIR-Hive | 2021-04-16 08:34 – 09:33 |

| SHIR-SAP | 2021-04-16 08:34 – 09:33 |

| SOC-FW-RDP | 2021-04-16 08:34 – 09:00 |



!\[Timeline Evidence](screenshots/when\_activity.png)



Limited data to confirm if activity continued beyond this window.



---



\## WHERE

Activity originated from internal hosts `SHIR-Hive`, `SHIR-SAP`, and `SOC-FW-RDP`,  

suggesting an attack via RDP or Windows authentication services.



---



\## WHY

Likely an automated attacker attempting to gain access to privileged accounts via brute-force or password spray.  

If these hosts are internet-facing or relay services, external actors may be involved.



---



\## HOW

Automated tool or script iterating credentials against accounts over RDP / domain authentication.  

The hostname `SOC-FW-RDP` indicates a remote desktop front end likely used for testing or management.



---



\## Supporting KQL Queries

```kql

// Failed logons by host

SecurityEvent\_CL

| where EventID\_s == "4625"

| summarize FailedAttempts = count() by Computer, Account\_s

| top 10 by FailedAttempts desc

```



\# Day 8 - Bookmark \& Manual Incident



\## Objective

Use Microsoft Sentinel to identify a notable pattern in Office 365 activity logs, bookmark the finding, and create a manual incident for further investigation.



---



\## Tools \& Concepts

\- Microsoft Sentinel  

\- OfficeActivity\_CL table  

\- KQL (Kusto Query Language)  

\- Bookmarks \& Manual Incidents  

\- SOC Investigation Workflow  



---



\## KQL Query

```kql

OfficeActivity\_CL

| where Operation\_s == "FileAccessed"

```

\### Purpose:

Retrieve Office 365 file-access events to review for unusual activity such as access from new or unexpected IP addresses.

\### Why It's Important:

Manual incidents help analysts capture context that automated detections may miss.

They demonstrate the ability to:

\- Recognize suspicious behavior during proactive log review

\- Escalate findings with supporting evidence

\- Maintain clear documentation for peer validation

!\[Bookmark Abnormal IP)](Day8-Bookmark-and-Manual-Incident/screenshots/ms\_30-day\_challenge-bookmark.png)

\### Observation:

\- The FileAccessed query showed activity from an unusual IP address.

\- A bookmark was created for further review.

\- May indicate suspicious or unauthorized access requiring investigation.



\## MITRE ATT\&CK Mapping

| Tactic            | Technique      | ID    |

| ----------------- | -------------- | ----- |

| Credential Access | Brute Force    | T1110 |

| Execution         | User Execution | T1204 |

| Defense Evasion   | Valid Accounts | T1078 |



\## Recommendations

1\. Implement and enforce account lockout policy for failed login thresholds.

2\. Require Multi-Factor Authentication (MFA) for all privileged and remote accounts.

3\. Audit RDP and administrative access to validate legitimate use.

4\. Monitor for continued failed logon spikes and create dynamic alerts for Event ID 4625.

5\. Restrict RDP exposure to internal networks only.



\## 🪞 Reflection

This incident reinforced my understanding of how failed logon patterns can signal early-stage brute-force attacks.

Correlating Event IDs 4625 and 4624 helped confirm that no compromise occurred, while visualizing the data clarified attack timing and scope.

Going forward, I plan to develop automated Sentinel rules and playbooks to detect similar behavior proactively.





\# Day 29 - Microsoft Defender XDR Incident Report



\*\*Alert:\*\* Hands-on Keyboard Attack via Possible Credential Misuse



\*\*Serverity:\*\* High



!\[XDR-Incident](Day29-Final-Mini-Project/xdr-incident.png)

\*Figure 1 - Microsoft Defender XDR incident overview showing high-severity alerts.\*





\## 1. Findings



\### Title:  

Hands-on Keyboard Activity via Possible Credential Misuse



\### Timeframes:

\- First Malicious Activity: 2025-11-22 05:55 UTC

\- Second Activity Wave: 2025-11-24 05:12–05:29 UTC



\### Host

\- mydfir-ndean-vm



\### IOC Domain

\- None observed before compromise



\### IOC IPs

\- 45.76.129.144 (foreign IP, London UK — impossible travel indicator)

\- 76.31.117.80 (expected region, initial login source)



\### Possible Malware / Tooling

\- HackTool:Win32/Mimikatz

\- HackTool:Win32/Mimikatz!pz

\- HackTool:Win32/Mimikatz!MSR

\- Trojan:PowerShell/Mimikatz.A

\- SOAPHound

\- AdFind

\- BadPotato





!\[Initial Mimikatz Detection](Day29-Final-Mini-Project/Intial-mimikatz-detection.png) 

\*Figure 2 - Initial Mimikatz credential-theft detection on the compromised host.\*



\## 2. Investigation Summary



Between November 22, 2025 at 11:55 UTC and November 24, 2025 at 11:29 UTC, Microsoft Defender XDR observed malicious activity on mydfir-ndean-vm tied to the account AzureAD\\JennySmith (jsmith). The incident began immediately after successful RemoteInteractive logins from two geographically inconsistent IP addresses, indicating likely credential misuse.



The first wave (starting Nov 22, 11:55 UTC) involved Mimikatz execution, interactive PowerShell activity, and initial domain discovery. The second wave (from Nov 24, 11:12–11:29 UTC) included continued credential-theft attempts, expanded AD reconnaissance using AdFind and SOAPHound, and a blocked privilege-escalation attempt with BadPotato.



Defender blocked or remediated all malicious activity. No successful privilege escalation, lateral movement, or data exfiltration occurred, and activity remained contained to mydfir-ndean-vm.



\## 3. Cross-Domain Correlation (Email → Identity → Endpoint)



\### 3.1 Email – Phishing Attempt (Initial Vector)





!\[Phishing Email](Day29-MiniProject-IncidentInvestigation/screenshots/phishing-email-sent.png)

\*Figure 3 - Phishing email providing the likely initial credential exposure point.\*



\- User received a phishing email containing a suspicious link

\- Defender for Office logged the message and performed Safe Links scanning

\- No confirmed click event, but email provides a credible source for credential exposure



\#### Email → Identity Connection:

Phishing email precedes risky sign-in — indicating possible credential compromise.



\### 3.2 Identity – Risky Sign-in / Impossible Travel



\#### Risky Sign-In Query - Identify Risky Sign-in From a Foreign IP



```kql

// Risky Sign-In (Foreign Location / Impossible Travel)

DeviceLogonEvents

| where DeviceName == "mydfir-ndean-vm"

| where LogonType contains "RemoteInteractive" or LogonType contains "Network"

| where RemoteIP != "76.31.117.80"   // expected region IP

| project Timestamp, AccountName, LogonType, RemoteIP, ActionType

| order by Timestamp asc

```



\##### What this query does:



\- Filters to interactive or network logons on the victim VM

\- Excludes your known “home region” IP to surface foreign activity

\- Shows only successful RemoteInteractive logons from unexpected IPs

\- Helps confirm credential misuse from 45.76.129.144





!\[Risky Signin](Day29-MiniProject-IncidentInvestigation/screenshots/risky-signin.png)



\*Figure 4.1 - Successful foreign RemoteInteractive logons from 45.76.129.144 indicating credential misuse and potential impossible travel.\*



\#### Impossible Travel Query - Detect “Impossible Travel” Between Logons



```kql

//Impossible Travel

DeviceLogonEvents

| where DeviceName == "mydfir-ndean-vm"

| where AccountName == "jsmith"

| order by Timestamp asc

| extend NextTime = next(Timestamp), NextIP = next(RemoteIP)

| extend DiffMinutes = datetime\_diff("minute", NextTime, Timestamp)

| where RemoteIP != NextIP and DiffMinutes <= 60

| project Timestamp, AccountName, DeviceName, RemoteIP, NextIP, DiffMinutes

```



\##### What this query does:



\- Sorts all sign-ins for the compromised account

\- Compares each login with the next login (timestamp + IP)

\- Calculates time between the two logons

\- Flags cases where:

&nbsp;	- IP changes location, AND

&nbsp;	- The time between logons is too short to travel physically

\- This helps strengthen the case of impossible travel and strongly supports credential compromise





!\[Impossible Travel](Day29-MiniProject-IncidentInvestigation/screenshots/Impossible-Travel1.png)



\*Figure 4.2 — Impossible Travel event showing rapid IP change from expected region (76.31.117.80) to foreign IP (45.76.129.144).\*



\##### Why this matters

\- Two sign-ins happen back-to-back from geographically incompatible IPs

\- Entra ID flags the event as Impossible Travel

\- The login succeeds, which means credentials were valid

\- This ties directly back to the phishing email earlier in the chain



\##### Identity → Endpoint Connection:

Minutes after the foreign login, hands-on-keyboard activity attacker appear on the endpoint, signaling a progression from identity compromise to endpoint compromise.



\### 3.3 Endpoint – Hands-on Keyboard Attack Activity



\#### Attacker Timeline Query



```kql

//Attacker Timeline

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   EventTable,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   AccountSid,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   InitiatingProcessAccountSid,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   InitiatingProcessCommandLine,

&nbsp;   EffectiveFolderPath,

&nbsp;   ProcessRemoteSessionIP,

&nbsp;   InitiatingProcessRemoteSessionIP

```





\##### What this query does:



\- Builds a unified attacker timeline by unioning multiple Microsoft Defender tables

\- Filters activity to \*\*mydfir-ndean-vm\*\* to look at activity from the system the attacker actually touched.

\- Anchor the timeline to the known time of compromise \*\*Timestamp > datetime(2025-11-22T11:48:53.8720476Z)\*\*

\- Tracks hands-on-keyboard activity from the attacker by isolating actions tied to that session 

\- Normalize file/process paths with \*\*EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)\*\*, giving me a single folder path even though different tables store it in different columns.





!\[Attacker Timeline](Day29-MiniProject-IncidentInvestigation/screenshots/Attacker-Timeline.png)



\*Figure 5 — Attacker session timeline showing interactive commands and processes executed directly after initial access.\*





Minutes after risky sign-in, endpoint logs show post-authentication activity executions 



\- Ran Mimikatz for credential harvesting

\- Conducted interactive PowerShell sessions

\- Performed Active Directory discovery using AdFind

\- Attempted privilege escalation via BadPotato.exe

\- No evidence of BadCastle enumeration

\- Attempted RDP lateral movement, which was blocked

\- Attacker transitioned from identity compromise to full endpoint exploitation attempt.



\#### Mimikatz Variants



```kql

// Mimikatz variants

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "mimi"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   EffectiveFolderPath

```



!\[Mimikatz Variants](Day29-MiniProject-IncidentInvestigation/screenshots/mimikatz-variants.png)



\*Figure 6 — Mimikatz components created and executed in rapid succession, showing hands-on-keyboard credential-theft activity immediately following the attacker’s remote logon.\*



\#### Interactive PowerShell



```kql

//Interactive PowerShell

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "powershell"

or EffectiveFolderPath contains "pwsh"

and ProcessCommandLine !has "-File"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   InitiatingProcessCommandLine,

&nbsp;   EffectiveFolderPat

```



!\[Interactive PowerShell](Day29-MiniProject-IncidentInvestigation/screenshots/Interactive-Powershell.png)



\*Figure 7 — Early attacker activity showing PowerShell execution, browser launch, named pipe usage, and repeated memory manipulation events (NtProtectVirtualMemory) occurring immediately after the foreign interactive logon, indicating hands-on-keyboard post-compromise actions.\*



\#### Discovery tools



```kql

// Discovery tools - AdFind 

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "adf"

or EffectiveFolderPath contains "adfind"

or ProcessCommandLine contains "adf"

or AdditionalFields contains "adf"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   EffectiveFolderPath

```



!\[Discovery Tools](Day29-MiniProject-IncidentInvestigation/screenshots/adfind.png)



\*Figure 8 — Second activity wave showing AdFind and SOAPHound execution via PowerShell, followed by AV detections and file changes indicating renewed discovery attempts.\*



\#### Privilege Escalation 



```kql

//privilege escalation - Bad Potato

union isfuzzy=true withsource=EventTable

&nbsp;   DeviceLogonEvents,

&nbsp;   DeviceProcessEvents,

&nbsp;   DeviceImageLoadEvents,

&nbsp;   DeviceEvents,

&nbsp;   DeviceFileEvents

| where DeviceName == "mydfir-ndean-vm"

| where Timestamp > datetime(2025-11-22T11:48:53.8720476Z)

| where    

&nbsp;   ProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or InitiatingProcessRemoteSessionIP == "45.76.129.144"

&nbsp;   or AccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

&nbsp;   or InitiatingProcessAccountSid == "S-1-12-1-1130201530-1243223228-2140479906-3749068551"

| extend EffectiveFolderPath = coalesce(FolderPath, InitiatingProcessFolderPath)

| where EffectiveFolderPath contains "bad"

or ProcessCommandLine contains "bad"

or AdditionalFields contains "bad"

| order by Timestamp asc

| project

&nbsp;   Timestamp,

&nbsp;   ActionType,

&nbsp;   AccountName,

&nbsp;   InitiatingProcessAccountName,

&nbsp;   FileName,

&nbsp;   ProcessCommandLine,

&nbsp;   InitiatingProcessFileName,

&nbsp;   EffectiveFolderPath

```



!\[Privilege Escalation](Day29-MiniProject-IncidentInvestigation/screenshots/badpotato.png)



\*Figure 9 — BadPotato privilege-escalation attempts detected and blocked, followed by related file modifications during the second activity wave.\*



\## 4. WHO / WHAT / WHEN / WHERE / WHY / HOW



\### WHO



\- Activity tied to the compromised account AzureAD\\JennySmith (jsmith / jennysmith).

\- The activity is tied to the compromised user account AzureAD\\JennySmith (jsmith).

\- The attacker authenticated using valid credentials from a foreign IP (45.76.129.144) not associated with the legitimate user.

\- All hands-on-keyboard actions were executed under this identity after the unauthorized login.



\### WHAT



\- The attacker performed credential theft (Mimikatz variants), AD discovery (AdFind, SOAPHound), and privilege-escalation attempts (BadPotato).

\- Multiple malicious files were created and executed, all originating from PowerShell sessions.

\- Defender detected and blocked these actions, preventing further escalation or lateral movement.



\### WHEN



Identifies when the attacker activity occurred and how events progressed over time.

Key Timestamps:

\- Foreign login: November 22, 11:48 UTC

\- First Activity Wave: November 22, 12:55 UTC

\- Blocked RDP lateral movement: 13:10 UTC

\- Second Activity Wave: Nov 24, 11:12–11:29 UTC

\- No malicious activity after 11:48 UTC, Nov 24



Put Screenshot HERE: 

!\[Associated Processes](Day29-Final-Mini-Project/associated-processes.png)

\*Figure 7 — Correlated processes executed under the compromised account during the attacker session.\*



\- Timeline shows activity beginning shortly after the foreign RemoteInteractive logon

\- Attacker actions appear in multiple event sources (DeviceProcessEvents, DeviceEvents, DeviceLogonEvents, DeviceNetworkEvents)

\- Events labeled "Likely attacker" confirm correlation across logons, processes, named pipes, and DPAPI access

\- Process execution under jennysmith occurs minutes after the initial compromise, showing rapid post-logon activity



The sequence reflects a continuous attacker session, with actions increasing in frequency over the identified timeframe



\### WHERE



\- All malicious activity occurred on host mydfir-ndean-vm.

\- Actions originated through RemoteInteractive logons, followed by execution under powershell.exe.

\- EffectiveFolderPath values show payloads placed and executed from:



&nbsp;	- `C:\\Users\\JennySmith\\AppData\\...`

&nbsp;	- `C:\\AtomicRedTeam\\tmp\\...`

&nbsp;	- `C:\\Windows\\System32\\WindowsPowerShell\\...`



\### WHY



\- The attacker’s likely objectives were:

&nbsp;	- Steal credentials for privilege escalation or lateral movement

&nbsp;	- Enumerate the environment to identify valuable targets

&nbsp;	- Attempt local privilege escalation via BadPotato

\- These activities align with early-stage intrusion behavior following credential compromise.



\### HOW



\- The compromise likely began with credential phishing, evidenced by a suspicious email received prior to the foreign login.

\- The attacker authenticated with valid credentials from an unexpected location (“impossible travel”).

\- After logging in, the attacker:

&nbsp;	- Launched PowerShell interactively

&nbsp;	- Loaded Mimikatz components to harvest credentials

&nbsp;	- Used discovery tools (AdFind, SOAPHound)

&nbsp;	- Attempted privilege escalation with BadPotato

\- Defender blocked these efforts before lateral movement or domain compromise occurred.





\## 5. Investigation Timeline Highlight



| Date              | Time (UTC)        | Event Description                                                                 |

|-------------------|-------------------|-----------------------------------------------------------------------------------|

| \*\*Nov 22, 2025\*\*  | 11:12             | Remote logon from \*\*76.31.117.80\*\* (expected region)                              |

|                   | 11:48             | Foreign logon from \*\*45.76.129.144\*\* → \*Impossible travel detected\*               |

|                   | 11:54             | First \*\*Mimikatz\*\* detection                                                      |

|                   | 11:55             | Hands-on-keyboard activity begins (interactive PowerShell)                        |

|                   | 11:57–12:02       | \*\*Credential theft attempts\*\* — Mimikatz components created/executed              |

| \*\*Nov 24, 2025\*\*  | 11:11             | Suspicious PowerShell activity begins                                             |

|                   | 11:18–11:28       | Multiple \*\*Mimikatz\*\* variants detected                                           |

|                   | 11:25–11:28       | \*\*Discovery \& Recon tools executed\*\*: AdFind, whoami, SOAPHound                   |

|                   | 11:25             | \*\*Privilege escalation attempt\*\* using `BadPotato.exe` (blocked)                  |

|                   | 11:27             | Ransomware-linked behavior alert triggered                                        |

|                   | 11:48             | No further malicious activity recorded                                            |







\## 6. Recommendations





\### Enforce MFA and Strengthen Identity Protections

&nbsp;	- Require MFA for all users

&nbsp;	- Enable Entra ID “Risky Sign-ins” and “Risky Users”



\### Harden Endpoint Configurations and Limit Post-Exploitation Tooling

&nbsp;	- Deploy endpoint EDR prevention policies that stop known tools

&nbsp;	- Ensure PowerShell logging is enabled for traceability



\### Apply Least Privilege and Review User Access

&nbsp;	- Audit privileged groups regularly	

&nbsp;	- Restrict ability to run PowerShell for non-administrative users where feasible



\### Endpoint Actions

&nbsp;	- Consider isolating or re-imaging mydfir-ndean-vm

&nbsp;	- Review RDP exposure and harden remote access

&nbsp;	- Validate firewall and remote access policies



\### Conduct User Security Awareness and Phishing Training

&nbsp;	- Link hygiene and credential theft indicators

&nbsp;	- Run simulated phishing campaigns to reinforce behavior





\## 7. Conclusion



Based on the available data, the activity observed on mydfir-ndean-vm appears confined to early-stage intrusion behaviors involving credential misuse, reconnaissance, and attempted execution of credential-theft tools. All malicious tooling appears to have been blocked or remediated by Microsoft Defender, and no evidence was identified showing further spread, persistence, or data compromise.



This incident began with a compromised user account `jsmith/jennysmith` on `mydfir-ndean-vm`, leading to unauthorized remote access from a foreign IP. Once connected, the attacker attempted credential theft using multiple Mimikatz variants, conducted discovery with AdFind and SOAPHound, and attempted privilege escalation through BadPotato. Defender intercepted each phase of the attack chain, preventing the attacker from gaining elevated privileges or moving laterally within the environment.



No sensitive data was accessed, no persistence mechanisms were established, and no signs of ransomware deployment or exfiltration were observed. The activity was fully contained on mydfir-ndean-vm, and the attack was effectively neutralized before achieving its objectives.



