# Scattered Spider / SLH Alliance: Defensive Playbook

MITRE G1015. Aliases: Octo Tempest (Microsoft, current), UNC3944 (Mandiant),
Muddled Libra (Unit 42), Scatter Swine (Okta), 0ktapus, Storm-0875 (earlier
Microsoft designation, consolidated into Octo Tempest).

As of 2025 to 2026, increasingly operating as part of the "Scattered Lapsus$
Hunters" (SLH) alliance: Scattered Spider handles initial access and social
engineering, ShinyHunters handles large-scale data exfiltration tooling, and
LAPSUS$ contributes extortion and public leak-site pressure. The alliance
has marketed a Ransomware-as-a-Service offering ("shinysp1d3r"). Financial
services and insurance are named as priority targets in 2025 to 2026
reporting, with roughly 700 Scattered Spider-pattern domains registered in
2025 alone.

Full narrative writeup: [LinkedIn Article link to be added]

> IOCs for this actor rotate weekly and are intentionally omitted here. This
> playbook maps methodology, detection logic, and response actions, which
> stay valid far longer than any specific domain or hash.

> A note on attribution: this actor's own claims of responsibility, made on
> Telegram or leak sites, should never be treated as confirmed attribution.
> SLH publicly claimed the September 2025 Jaguar Land Rover attack, and a
> subsequent investigation reported by the New York Times in June 2026
> traced that breach to a separate Russian operation. Treat self-reported
> credit as marketing, not evidence.

---

## How to Use This Document

This is built for three moments:

1. Building coverage. Use the Detection Logic section to write and test
   rules before an incident happens.
2. Mid-investigation triage. Use the Triage and Prioritization section to
   decide how urgently a specific alert needs escalation.
3. Confirmed intrusion. Use the Response Checklist to move through
   containment in the right order, since doing these steps out of order can
   tip off the actor or lose evidence.

---

## Attack Chain, MITRE Mapping, and Confidence

Every technique below was checked against its official MITRE tactic
categorization, not assumed from the surrounding narrative. Confidence
reflects how directly each technique is documented against this actor
specifically.

| Stage | Technique | MITRE ID | Confidence |
|---|---|---|---|
| Reconnaissance | Phishing for information: pretexting a target via help desk vishing or SMS to elicit credentials or reset actions | T1598 | High, this is their signature behaviour, documented since 2022 |
| Initial Access | Spearphishing / AiTM phishing domains mimicking SSO or a legitimate app ("target-sso[.]com" pattern) | T1566, T1566.002 | High |
| Credential Access | Steal Application Access Token: OAuth device-code phishing using an attacker-registered app impersonating a legitimate tool, broad scope grant via vishing-guided device auth flow | T1528 | High for SLH-alliance campaigns since mid-2025, documented in the Salesforce/DataLoader campaigns |
| Credential Access | MFA push bombing / fatigue | T1621 | High, directly documented against Scattered Spider by MITRE (procedure example under G1015) |
| Discovery | AADInternals, BloodHound: AD account and domain trust enumeration | T1087, T1482 | High |
| Persistence, Privilege Escalation | Direct AD account attribute modification via SAMR (active change, not enumeration) | T1098 | Medium, documented in specific incidents, not universal |
| Command and Control | Legitimate RMM abuse (AnyDesk, TeamViewer, ScreenConnect) | T1219 | High |
| Command and Control | Tunneling via ngrok, Chisel, Tailscale, Teleport | T1572 | High |
| Defense Evasion | BYOVD used to disable or kill EDR (STONESTOP, POORTRY) | T1562.001 (disabling the tool), T1068 (exploiting the vulnerable driver itself) | Medium, seen at ransomware stage, not every intrusion reaches this stage |
| Credential Access | Mimikatz, secretsdump for local credential dumping | T1003 | High |
| Lateral Movement | RDP, PsExec, GPO abuse, largely manual | T1021, T1570 | High |
| Impact | DragonForce ransomware targeting VMware ESXi | T1486 | Medium, one of several ransomware affiliations, not exclusive |
| Exfiltration | SSH to VPS providers, S3, cloud storage/messaging; large-scale SaaS API extraction (ShinyHunters-alliance campaigns) | T1567 | High |

---

## Detection Logic by Stage

Each entry includes the hunting logic, not just the data source, so an
analyst can build this directly rather than re-deriving it.

### 1. Help-desk-initiated credential reset abuse

The single highest-value detection for this actor. Logic: flag any password
reset or MFA method change performed by IT/help desk staff where a new
device registration or remote access tool execution follows within a short
window, with no matching change ticket.

```spl
index=identity sourcetype=okta_idp OR sourcetype=entraid_audit
(eventtype="user.mfa.factor.update" OR eventtype="user.account.reset_password"
 OR operation="Reset user password" OR operation="Update StrongAuthenticationMethod")
| eval reset_time=_time
| join user_id
    [ search index=identity sourcetype=okta_idp OR sourcetype=entraid_audit
      (eventtype="device.registration" OR eventtype="user.session.start")
      | eval followup_time=_time ]
| eval delta_minutes=(followup_time-reset_time)/60
| where delta_minutes >= 0 AND delta_minutes <= 60
| lookup change_tickets ticket_user AS user_id OUTPUT ticket_id
| where isnull(ticket_id)
| table _time, user_id, reset_time, followup_time, delta_minutes, src_ip, device_id
```

**Tuning:** exclude known bulk password reset events (post-breach forced
resets, password policy rollouts) by excluding events where more than N
users are reset within the same 10-minute window from the same admin
account, since that pattern is administrative, not targeted.

### 2. OAuth device-code / broad-scope app authorization

Newest and currently least-covered vector. Logic: alert on any new OAuth
application granted refresh token generation or full API scope, especially
outside a change-managed integration process.

```spl
index=saas sourcetype=salesforce_setup_audit OR sourcetype=entraid_app_consent
(action="ConnectedApp" OR action="Consent to application")
scope IN ("api", "refresh_token", "full", "offline_access")
| lookup approved_integrations app_id OUTPUT approved
| where isnull(approved)
| stats count min(_time) as first_seen values(user) as authorizing_user by app_name, app_id, scope
| sort - count
```

**Tuning:** maintain an allowlist of approved integrations (`approved_integrations`
lookup) and review it monthly. This is the single highest false-negative
risk in the whole playbook if the allowlist goes stale, since a new
legitimate integration will otherwise look identical to the malicious
pattern.

### 3. MFA push bombing

```spl
index=identity sourcetype=okta_idp OR sourcetype=entraid_audit
eventtype="user.authentication.auth_via_mfa" result="FAILURE" OR result="CHALLENGE"
| bucket _time span=5m
| stats count by user_id, _time
| where count >= 5
```

### 4a. Tunneling infrastructure (network connections)

Detects outbound connections to known tunneling providers.

```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=3
(dest_port=443 OR dest_port=80)
process_name!="chrome.exe" process_name!="msedge.exe" process_name!="firefox.exe"
| lookup known_tunnel_domains dest_ip OUTPUT is_tunnel_provider
| where is_tunnel_provider=1 OR match(dest_hostname, "(?i)ngrok|tailscale|teleport\.sh|chisel")
| stats count values(process_name) as processes by host, dest_hostname, user
```

**Tuning:** false-positives against legitimate engineering use of ngrok or
Tailscale. Scope the lookup to exclude an approved engineering asset group,
and treat hits from finance, treasury, or admin workstations as high
priority regardless of allowlist status.

### 4b. Named pipe creation and connection

Network connection logging does not capture named pipe activity. This
requires Sysmon Event IDs 17 and 18, a different event source entirely,
used to catch SMB-based pivoting and inter-process C2 communication that
4a will miss completely.

```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
(EventCode=17 OR EventCode=18)
NOT [ | inputlookup known_good_pipe_names.csv | fields pipe_name ]
| eval is_system_process=if(match(process_name, "(?i)svchost|lsass|services|wininit"), 1, 0)
| where is_system_process=0
| stats count values(EventCode) as event_types by host, process_name, pipe_name, user
| sort - count
```

**Tuning:** build the `known_good_pipe_names` lookup from a 30-day baseline
per host role before enabling this in production; pipe creation is noisy
without a baseline, and this query will be unusable without it.

### 5. BYOVD / unexpected driver load preceding EDR interruption

```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=6
NOT [ | inputlookup known_good_drivers.csv | fields driver_hash ]
| join host
    [ search index=edr_status sourcetype=edr_service_events
      (event="service_stop" OR event="service_crash")
      | eval edr_stop_time=_time ]
| eval delta_seconds=(edr_stop_time-_time)
| where delta_seconds >= 0 AND delta_seconds <= 300
| table _time, host, driver_name, driver_hash, edr_stop_time
```

This is a high-confidence, low-volume detection. Treat any hit as an
immediate escalation, not a queued alert, since it typically precedes
ransomware deployment by minutes to hours.

### 6. ESXi / hypervisor-targeted staging

```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=3
(process_name="python.exe" OR process_name="python3.exe" OR process_name IN ("pwsh.exe","powershell.exe"))
dest_port=443
| lookup vcenter_esxi_hosts dest_ip OUTPUT is_hypervisor
| where is_hypervisor=1
| lookup known_automation_hosts src_ip OUTPUT is_approved
| where isnull(is_approved)
```

---

## Triage and Prioritization

Not every hit needs the same response speed. Use this to decide.

| Signal | Priority | Target response time |
|---|---|---|
| BYOVD detection (Section 5) | Critical | Immediate, page on-call |
| New broad-scope OAuth grant on a finance/treasury-adjacent account | Critical | Immediate |
| Help-desk reset followed by new device, no ticket (Section 1) | High | Within 1 hour |
| ESXi-directed process activity from non-approved host | High | Within 1 hour |
| MFA push bombing (Section 3) | Medium | Within 4 hours, verify with the user directly by a channel other than the one that triggered the alert |
| Named pipe anomaly (Section 4b) | Medium | Within 4 hours |
| Tunnel infrastructure hit outside engineering allowlist (Section 4a) | Medium | Within 4 hours |
| Tunnel infrastructure hit within engineering allowlist | Low | Weekly review |

**Why direct verification matters for MFA push bombing specifically:** do
not verify with the user over the same phone number or messaging channel
the actor may already control if a SIM swap is suspected. Use a
pre-established out-of-band method, in person or a company badge-verified
callback line.

---

## Response Checklist (Confirmed Intrusion)

Order matters here. Doing these out of sequence can alert the actor before
containment is complete, or destroy evidence needed for the retrospective.

1. Do not immediately disable the compromised account. Scattered Spider
   monitors for signs of detection and will accelerate to ransomware
   deployment if they sense they have been caught. Move to silent
   containment first.
2. Revoke active sessions and OAuth tokens for the account, not just the
   password, since password reset alone does not invalidate an
   already-issued OAuth refresh token or active session.
3. Isolate any host that touched tunnel infrastructure or showed the
   BYOVD pattern via EDR network isolation, not local firewall rules the
   actor may already have visibility into.
4. Pull vCenter/ESXi admin logs immediately if any hypervisor-directed
   activity was seen. This environment often has short log retention;
   preserving it early matters more here than on endpoints.
5. Notify treasury/finance operations leads directly if any
   treasury-adjacent account was touched, before wider IR communications go
   out, since this actor's alliance partners monetize through both
   ransomware and public data leak pressure, and the response may differ.
6. Only after containment, disable the account and rotate credentials.
7. Review OAuth app consent grants organization-wide, not just for the
   affected account, since a single vished user is often used to establish
   a foothold app with access broader than that one user's own permissions.

---

## Actor-Specific Signal (vs. generic account takeover)

- Fluent, accent-free English social engineering.
- Identity or OAuth compromise leading to cloud admin/API access within
  hours, not days.
- Legitimate/dual-use tooling preferred over custom malware.
- Sector-focused campaigns lasting weeks to months, then rotating.
- As of 2025 to 2026, operating within the SLH alliance. Expect
  ShinyHunters-style bulk data extraction and LAPSUS$-style public leak
  pressure alongside classic Scattered Spider initial access.
- Late-stage pivot to VMware ESXi-targeted ransomware if uncaught early.
- Self-claimed credit on Telegram or leak sites is not attribution. Verify
  independently before treating any specific incident as confirmed.

---

## References

- [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/)
- [MITRE ATT&CK T1621 Procedure Examples for Scattered Spider](https://attack.mitre.org/techniques/T1621/)
- [CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Microsoft: Protecting Customers from Octo Tempest Attacks](https://www.microsoft.com/en-us/security/blog/2025/07/16/protecting-customers-from-octo-tempest-attacks-across-multiple-industries/)
- [CrowdStrike: Scattered Spider Escalates Attacks Across Industries](https://www.crowdstrike.com/en-us/blog/crowdstrike-services-observes-scattered-spider-escalate-attacks/)
- [ReliaQuest: ShinyHunters/Scattered Spider Collaboration](https://reliaquest.com/blog/threat-spotlight-shinyhunters-data-breach-targets-salesforce-amid-scattered-spider-collaboration/)
- [Resecurity: Trinity of Chaos, the LAPSUS$/ShinyHunters/Scattered Spider Alliance](https://www.resecurity.com/blog/article/trinity-of-chaos-the-lapsus-shinyhunters-and-scattered-spider-alliance-embarks-on-global-cybercrime-spree)
- [Infosecurity Magazine: Financial Services Could Be Next in Line for ShinyHunters](https://www.infosecurity-magazine.com/news/financial-services-next-line/)
- [Push Security: Analyzing the Instructure Breach](https://pushsecurity.com/blog/analyzing-the-instructure-breach)
- [New York Times, via Infosecurity Magazine: Russian Hackers Accused of Destructive Attack on Jaguar Land Rover](https://www.infosecurity-magazine.com/news/russian-hackers-destructive-jaguar/)
- [GuidePoint Security: Worldwide Web, Scattered Spider TTPs](https://www.guidepointsecurity.com/blog/worldwide-web-an-analysis-of-tactics-and-techniques-attributed-to-scattered-spider/)
- [Splunk Security Research: Scattered Spider](https://research.splunk.com/stories/scattered_spider/)
