# Qilin (Agenda): Financial Services Access Paths and ATT&CK v20 Mapping

Reference for CTI analysts. Reported fact, vendor assessment and analyst inference are kept separate.
Data as of 19 October 2026. Technique IDs and names follow ATT&CK v20 (released 13 October 2026), which includes the v19 Defense Evasion split.

## Naming

| Source | Name | Note |
|---|---|---|
| MITRE ATT&CK | Qilin (S1242) | Associated software name: Agenda |
| MITRE ATT&CK | Water Galura (G1050) | Operators of the Qilin RaaS: payload generation, ransom negotiations, leak-site publication |
| MITRE ATT&CK | Moonstone Sleet (G1036) | Has deployed Qilin (Microsoft Threat Intelligence, Mar 2025). DPRK-linked actor, not a Qilin alias |
| Sophos MDR | STAC4365 | Sophos tracking name for the ScreenConnect-targeting activity in its January 2025 MSP case. Not a Qilin alias |

## Operating model

- RaaS. Affiliates are recruited on Russian-language forums and run intrusions (MITRE G1050, Sophos).
- Affiliate share: 80% up to $3M, 85% above, per Group-IB (infiltration, March 2023). Later reporting repeats these terms. Current terms are not independently confirmed.
- Payments reach the affiliate wallet first, then the operator takes a share (KELA, July 2023, via SANS).
- "Call Lawyer" panel feature announced June 2025 (Cybereason, via The Register).
- Double extortion. Halcyon reports exfiltration via Rclone, FTP and cloud services before encryption.
- Targets Windows, Linux and VMware ESXi (MITRE).

## Scale and rank (dataset-dependent)

| Source | Period | Finding |
|---|---|---|
| Check Point Research, State of Ransomware Q2 2026 | Q2 2026 | Qilin 279 leak-site victims, first for a fourth straight quarter, down 17% on Q1. The Gentlemen 269, ahead of Qilin in June (116 vs 72) |
| ReliaQuest | Q2 2026 | The Gentlemen 300, Qilin 289 |
| Check Point Research | 2026 | The Gentlemen's administrator identified as a former Qilin affiliate |

## Financial services indicators

- Black Kite 2026 Financial Services report (data Jan 2023 to Q1 2026): direct ransomware attacks on financial institutions +30% in 2025 and +76% YoY in Q1 2026. Distinct groups targeting the sector: 37 (2023), 45 (2024), 48 (2025). Qilin, Akira and Kill Security lead. 59 Qilin finance-sector incidents.
- Cyble, US BFSI H1 2026: Qilin, Akira and DragonForce account for nearly half of observed ransomware activity against the US financial sector.
- SOCRadar, 2026 Finance Threat Landscape: over 70% of finance ransomware incidents come from smaller or less established actors.
- The datasets disagree on concentration.

## Access path A: edge VPN (CVE-2026-50751)

| Item | Detail (Check Point unless noted) |
|---|---|
| Flaw | Authentication bypass, CVSS 9.3. Logic flaw in certificate validation during IKEv1 key exchange. Unauthenticated VPN session without a valid password |
| Affected products | Mobile Access / SSL VPN, Remote Access VPN, Spark Firewall. Versions R80.20.X (EOS), R80.40 (EOS), R81 (EOS), R81.10 (EOS), R81.10.X, R81.20, R82, R82.00.X, R82.10 |
| Exploitable only when all four hold (sk185033, per CSA Singapore and Check Point community guidance) | Remote Access VPN or Mobile Access enabled; IKEv1 enabled for remote access; legacy Remote Access clients accepted; gateway does not require a machine certificate |
| Timeline | Earliest known exploitation 7 May 2026. Investigation launched 4 June after suspicious activity. Advisory and hotfix 8 June. Exploitation increased in early June. Exploited about a month before a fix was available |
| Scope | Observed exploitation limited to a few dozen targeted organisations. One case with confirmed post-compromise activity by a Qilin affiliate |
| Attribution | Medium confidence: financially motivated actor using Qilin. Check Point also believes the infrastructure exploits other VPN flaws, including ones published by Palo Alto, Fortinet and F5 |
| Follow-on | Additional post-authentication activity is required to reach internal resources or escalate privileges |
| Response guidance | Audit logs and configuration back to 7 May. CISA added the CVE to KEV on 8 June, remediation due 11 June |
| Companion CVE | CVE-2026-50752 (CVSS 7.4), IKEv1 certificate validation, possible man-in-the-middle on site-to-site VPN. No exploitation observed. Hotfix sk185035 |

## Access path B: supplier trust

| Case | Reported detail |
|---|---|
| Sophos MDR (published 1 Apr 2025), January 2025 case | MSP administrator phished with a spoofed ScreenConnect login alert. Attacker authenticated as super administrator, pushed a new ScreenConnect instance (file `ru.msi`) to multiple managed customers, then deployed Qilin |
| Korean Leaks, Sept 2025 (Bitdefender) | Three publication waves: 10 victims on 14 Sept, 9 between 17 and 19 Sept, 9 between 28 Sept and 4 Oct (28 public in total). Over 1M files, 2 TB. Bitdefender's analysis suggests a single compromised upstream provider with privileged access to victim networks. Korean media (JoongAng Daily, 23 Sept 2025) named the MSP GJTec |
| Black Kite | South Korea: 0 finance ransomware disclosures in 2023 and 2024, 32 in 2025, nearly all in one month. Black Kite describes one MSP compromise cascading into financial institutions |
| Attribution caveat | Bitdefender assessed possible Moonstone Sleet involvement. Not confirmed |

### Count reconciliation (these measure different things; do not add or compare directly)

| Figure | What it counts | Source |
|---|---|---|
| 25 | Qilin victims in South Korea in September 2025 (24 in the financial sector), against a prior average of about 2 per month | Bitdefender |
| 28 | Publicly listed Korean Leaks victims across three waves, 14 Sept to 4 Oct 2025 | Bitdefender |
| 33 | Total Korean Leaks victims, of which 28 are public | Bitdefender |
| 32 | South Korean finance ransomware disclosures in 2025, nearly all in one month | Black Kite |

## Other documented access routes

- Cisco Talos could not definitively identify a single initial intrusion vector across its 2025 Qilin cases. It saw leaked credentials, and NTLM authentication attempts against multiple VPN accounts, in one case.
- Trend Micro's Linux-on-Windows case most likely began with credentials stolen by infostealers delivered through fake CAPTCHA pages (Trend's assessment), with MFA bypassed using harvested sessions.

## Technique mapping (ATT&CK v20)

Phase labels are descriptive, not ATT&CK tactic assignments. Items marked * are analyst mappings not listed on MITRE S1242.

| Phase | ID | Technique | Qilin procedure |
|---|---|---|---|
| Initial access | T1133* | External Remote Services | VPN sessions, including CVE-2026-50751 (Check Point) |
| Initial access | T1190 | Exploit Public-Facing Application | Exposed applications including Citrix and RDP (MITRE) |
| Initial access | T1078* | Valid Accounts | Credentials stolen by infostealers (Trend Micro) or leaked on the darknet (Cisco Talos) |
| Initial access | T1566.001 | Phishing: Spearphishing Attachment | Malicious attachments (MITRE) |
| Initial access | T1566.002 | Phishing: Spearphishing Link | Malicious links, spoofed ScreenConnect alert (MITRE, Sophos) |
| Initial access | T1199* | Trusted Relationship | MSP compromise feeding downstream customers (Sophos, Bitdefender) |
| Execution | T1204.001 | User Execution: Malicious Link | Lure-driven execution (MITRE) |
| Execution | T1204.002 | User Execution: Malicious File | Lure-driven execution (MITRE) |
| Execution | T1204.004* | User Execution: Malicious Copy and Paste | Fake CAPTCHA pages (Trend Micro assessment) |
| Remote tooling | T1219.002 | Remote Access Tools: Remote Desktop Software | Splashtop SRManager.exe runs a Linux binary on Windows (Trend Micro) |
| Remote tooling | T1071.002 | Application Layer Protocol: File Transfer Protocols | WinSCP transfers the Linux binary (Trend Micro) |
| Credential access | T1003.001 | OS Credential Dumping: LSASS Memory | Embedded Mimikatz module (MITRE, Picus) |
| Credential access | T1134 | Access Token Manipulation | Embedded Mimikatz module for token manipulation (MITRE, Picus) |
| Lateral movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Embedded PsExec (MITRE, Picus, Cisco Talos) |
| Lateral movement | T1570 | Lateral Tool Transfer | PsExec distributes a second encryptor (Cisco Talos) |
| Defense impairment | T1685 | Disable or Modify Tools | Terminates AV processes and services (MITRE). BYOVD with eskle.sys (Trend Micro), rwdrv.sys and hlpdrv.sys (Trend Micro, Oct 2025; Cisco Talos, Apr 2026) |
| Defense impairment | T1685.005 | Disable or Modify Tools: Clear Windows Event Logs | Clears event logs (MITRE) |
| Defense impairment | T1688 | Safe Mode Boot | Reboots into safe mode (MITRE) |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | GPO-pushed tasks, `TVInstallRestore` task (MITRE, Cisco Talos) |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | RunOnce entry (MITRE) |
| Policy | T1484.001 | Domain or Tenant Policy Modification: Group Policy Modification | Scheduled task pushed via GPO (MITRE) |
| Exfiltration | T1567.002* | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Rclone and cloud services (Halcyon). Help Net Security reads a hash in Check Point's CVE-2026-50751 IOCs as Rclone |
| Impact | T1486 | Data Encrypted for Impact | AES-256 or ChaCha20, RSA-protected keys (MITRE) |
| Impact | T1490 | Inhibit System Recovery | Shadow copy deletion, vCenter HA/DRS disabled (MITRE) |
| Impact | T1489 | Service Stop | Terminates specific services (MITRE) |
| Impact | T1529 | System Shutdown/Reboot | Backup server reboot (MITRE) |
| Discovery | T1673 | Virtual Machine Discovery | ESXi and vCenter enumeration (MITRE) |
| Discovery | T1082 | System Information Discovery | Platform detection: FreeBSD, ESXi, Nutanix AHV, Linux (MITRE) |
| Discovery | T1018 | Remote System Discovery | Domain host enumeration (MITRE) |
| Discovery | T1087.002 | Account Discovery: Domain Account | PowerShell cmdlets for domain users (MITRE, Cisco Talos) |

Mapping notes:
- BYOVD is a procedure, not a row. MITRE S1242 maps Qilin's AV termination to T1685.
- ATT&CK v19 (28 April 2026) retired the Defense Evasion tactic. It is now Stealth (TA0005) and Defense Impairment (TA0112). T1562, T1562.001 and T1562.006 were merged into T1685. Clear Windows Event Logs (formerly T1070.001) now appears as T1685.005 under T1685.

## Reported artifacts (not an IOC feed)

- `eskle.sys` (Trend Micro, Oct 2025).
- `rwdrv.sys` and `hlpdrv.sys`: named by Trend Micro (Oct 2025), dropped by a sideloaded `msimg32.dll` (for example via `FoxitPDFReader.exe`). Cisco Talos (Apr 2026) analysed the chain: `rwdrv.sys` is a signed vulnerable driver abused for physical memory access (a renamed ThrottleStop.sys in Talos's sample; other analyses report different underlying drivers under the same filename), and `hlpdrv.sys` terminates protected EDR processes via IOCTL `0x2222008`.
- Persistence command (Cisco Talos, Oct 2025): `schtasks /Create /TN TVInstallRestore /TR "C:\-INSTALLERS\TeamViewer_Host_Setup - <encryptor_2>.exe /RESTORE" /RU SYSTEM /SC ONLOGON /F`. `<encryptor_2>` is Talos's placeholder for the second encryptor's name.
- `ru.msi` pushed through ScreenConnect (Sophos).
- WinSCP or Splashtop SRManager.exe preceding a Linux ELF on a Windows host (Trend Micro).

## Law enforcement context (October 2026)

- North Rhine-Westphalia's interior and justice ministers say a 28-year-old Russian national, one of Qilin's leading figures in their account, was arrested in Japan in late May and transferred to Germany on 2 October.
- SecurityWeek reports he is wanted over a September 2024 attack on a German logistics company with more than $160,000 extorted. NRW's LKA and ZAC reportedly infiltrated and monitored the group for months.
- Interior Minister Reul's estimate: nearly 4,000 companies extorted worldwide since 2024, 150 in Germany.
- No reporting reviewed describes seizure of Qilin infrastructure. Qilin continued listing claims after the announcement (ransomware.live logged one on 13 October).

## Evidence boundary

| Category | Statement |
|---|---|
| Reported | CVE-2026-50751 exploitation window, scope and conditions. Korean Leaks wave counts. Sophos MSP case |
| Vendor assessment | Check Point: medium confidence the CVE-2026-50751 actor uses Qilin. Bitdefender: a single upstream provider is the likely access point for Korean Leaks |
| Not established | Moonstone Sleet involvement in Korean Leaks. Current affiliate revenue terms |
| Analyst inference | Supplier privilege and edge exposure are the controllable variables, not the Qilin brand |

## Intelligence requirements

1. Which edge VPN and firewall products do we run, with which legacy protocols enabled, and what is our audit window when a vendor discloses exploitation?
2. Which suppliers can push software or hold administrator access through RMM tools, and who holds those credentials?
3. Do we track affiliates by technique and access vector, with a separate alias table for operators and affiliates?
4. Do we detect exfiltration tooling (Rclone, WinSCP, cloud sync) before the encryption stage?

## Sources

- MITRE ATT&CK v20: S1242 Qilin, G1050 Water Galura, G1036 Moonstone Sleet, T1133, T1685.005 (live pages)
- Check Point: security advisory (8 Jun 2026, updated 11 Jun), sk185033, sk185035; State of Ransomware Q2 2026; The Gentlemen leak analysis
- CISA KEV addition (8 Jun 2026); Help Net Security (8 Jun 2026)
- Bitdefender, The Korean Leaks (24 Nov 2025, via The Hacker News); Korea JoongAng Daily (23 Sept 2025)
- Sophos MDR, Qilin affiliates spear-phish MSP ScreenConnect admin (1 Apr 2025)
- Trend Micro, Agenda ransomware Linux variant on Windows (23 Oct 2025); Cisco Talos, Uncovering Qilin attack methods (Oct 2025) and Qilin EDR killer infection chain (Apr 2026)
- Group-IB (via The Record, May 2023); SANS, Evolution of Qilin RaaS; Cybereason (via The Register, Jun 2025)
- Black Kite 2026 Financial Services Report; Cyble US BFSI H1 2026; SOCRadar 2026 Finance Threat Landscape; ReliaQuest Q2 2026
- SecurityWeek and Jiji Press (Oct 2026); NRW ministers' statements via dpa, ZDF and Tagesspiegel (Oct 2026)
