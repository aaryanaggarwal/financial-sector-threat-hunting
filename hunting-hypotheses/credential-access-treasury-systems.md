# Hunting Hypothesis: Credential Access Targeting Treasury Systems

## Hypothesis Statement

> "If a threat actor has achieved a foothold in a financial institution's network
> with the objective of fraudulent fund transfer (e.g. SWIFT, treasury management
> systems), they will prioritise credential access techniques that target accounts
> with treasury or payment authorisation privileges over broad-spectrum credential
> harvesting - because the value of compromise is concentrated in a small number
> of high-privilege accounts, not in volume."

This hypothesis is informed by patterns documented in Carbanak Group intrusions
against financial institutions, where adversaries deliberately spent extended
dwell time learning internal payment authorisation procedures before acting -
prioritising precision over speed.

---

## Why This Matters in Financial Services

Most credential access hunting focuses on volume signals - mass LSASS access,
brute force patterns, password spray detection. These are necessary but
insufficient for treasury-targeted intrusions.

Carbanak-style intrusions begin with a legitimate user executing a malicious payload, after which the actor expands access through privilege escalation, credential access, and lateral movement with the specific goal of compromising money processing services and financial accounts - establishing persistence to learn the institution's internal procedures before acting. Documented Carbanak operations went further than typical credential harvesting: the group recorded video of victim screens and logged keystrokes specifically to learn how employees operated internal banking and SWIFT software, effectively acquiring the operational knowledge of a bank employee without ever being onsite.

That dwell time, used for reconnaissance rather than immediate exfiltration, is
the detection opportunity. A hunt built around "who is touching treasury-adjacent
credentials, and is that normal for them" will surface this kind of intrusion
before funds move - generic credential dumping alerts often will not, because the
activity is low-volume and deliberately paced to avoid triggering them.

---

## Relevant Threat Activity

**Carbanak Group (MITRE G0008)** - tracked as the group responsible for large-scale bank heists, directly targeting financial institutions and manipulating banking infrastructure to steal funds via ATMs and SWIFT transfers.

Note: Carbanak Group is sometimes conflated with FIN7 in vendor reporting due to
shared tooling (the Carbanak backdoor). FIN7 (MITRE G0046) is a separate, financially motivated group that has also used the Carbanak backdoor but has primarily targeted retail, restaurant, hospitality, and point-of-sale environments rather than banks directly. This hypothesis is scoped to the Carbanak Group's documented treasury/SWIFT-targeting behaviour, not FIN7's POS-focused activity - worth keeping distinct when briefing stakeholders, since the two are frequently merged in open-source reporting.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Why it applies here |
|---|---|---|
| Credential Access | T1003.002 - OS Credential Dumping: SAM | Local credential harvesting on treasury workstations as a precursor to lateral movement |
| Credential Access | T1003.003 - OS Credential Dumping: NTDS | Domain-wide credential extraction if the actor escalates beyond a single workstation |
| Credential Access | T1003.004 - OS Credential Dumping: LSA Secrets | Service account credentials, often used by treasury/payment middleware |
| Credential Access | T1558 - Steal or Forge Kerberos Tickets | Kerberoasting against service accounts tied to treasury applications |
| Credential Access | T1056.001 - Input Capture: Keylogging | Capturing credentials for treasury/SWIFT applications not integrated with AD/SSO - a documented Carbanak technique |
| Collection | T1113 - Screen Capture | Recording treasury application workflows to learn transaction approval procedures - a defining Carbanak behaviour |
| Discovery | T1087 - Account Discovery | Reconnaissance to identify accounts with payment authorisation roles |
| Collection | T1114 - Email Collection | Reading internal communications to learn payment approval workflows |

---

## Hunt Approach

This is a hypothesis to investigate, not a single query - it requires correlating
across several data sources rather than one log type.

**Step 1 - Scope the asset population.**
Identify hosts and accounts associated with treasury, payments, and SWIFT
operations. This requires an accurate asset/identity inventory; without it, this
hunt cannot be meaningfully scoped.

**Step 2 - Baseline normal access patterns.**
For the scoped population, establish what normal looks like: which accounts
access these systems, from which hosts, during which hours, and via which
authentication methods. Treasury operations tend to be procedurally rigid, which
makes deviations more visible than in general user populations.

**Step 3 - Hunt for credential access events touching the scoped population.**
Cross-reference T1003 sub-technique indicators (LSASS access, SAM/NTDS reads,
LSA Secrets access) and T1558 Kerberoasting indicators (abnormal service ticket
requests) against the scoped host and account list from Step 1.

**Step 4 - Hunt for reconnaissance preceding the credential access event.**
Look for account discovery activity (T1087) or unusual access to internal
documentation/email related to payment workflows in the days or weeks prior.
This is where the "dwell time learning procedures" pattern becomes visible - the
intrusion rarely starts with the credential dump itself. Given Carbanak's
documented use of T1113/T1056.001, also look for unexplained screen recording
or input capture tooling (legitimate remote support tools abused, or unknown
processes hooking keyboard/display APIs) on treasury-scoped hosts.

**Step 5 - Correlate timing.**
A short interval between reconnaissance (Step 4) and credential access (Step 3),
against a treasury-scoped account, with no corresponding change ticket or
authorised access reason, is the highest-confidence indicator this hypothesis is
producing a true positive.

---

## Telemetry / Data Sources

| Source | What to pull |
|---|---|
| EDR / Sysmon | Event ID 10 (ProcessAccess) targeting `lsass.exe`, filtered to unusual `GrantedAccess` rights (e.g. `0x1010`, `0x1410`) from non-allowlisted processes |
| Windows Security Events | Event ID 4769 (Kerberos Service Ticket Requested) - watch for RC4 encryption downgrades (`0x17`) and excessive ticket requests from a single source; Event IDs 4624/4625 for logon anomalies on treasury-scoped accounts |
| EDR / Sysmon | Event ID 1 (Process Creation) for unexpected screen-capture or remote-access tooling (e.g. unauthorised VNC/RAT binaries, FFmpeg invoked outside known automation) on treasury-scoped hosts |
| Application Logs | SWIFT/Treasury application audit logs - baseline standard transaction timing, volume, and approval patterns to spot deviation |

---

## What Would Disprove This Hypothesis

Worth stating explicitly, since a hunt that can't be disproven isn't a hunt:

- If credential access activity against treasury-scoped accounts is found to be
  fully explained by legitimate administrative activity (patching, account
  provisioning, scheduled audits), the hypothesis is not supported for that
  instance.
- If the credential access event is attributable to an authorised vulnerability
  scanner (e.g. Nessus, Qualys) authenticating via a known service account, the
  hypothesis is disproven for that event - this is a common source of T1003
  false positives in enterprise environments and should be ruled out early.
- If no reconnaissance phase precedes the credential access event, this may
  indicate opportunistic rather than targeted activity, which falls outside
  the scope of this specific hypothesis.

---

## References

- [MITRE ATT&CK T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [MITRE ATT&CK T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)
- [MITRE ATT&CK T1056.001 - Input Capture: Keylogging](https://attack.mitre.org/techniques/T1056/001/)
- [MITRE ATT&CK Carbanak+FIN7 Evaluation](https://evals.mitre.org/enterprise/carbanak-fin7/)
- [MITRE ATT&CK G0008 - Carbanak](https://attack.mitre.org/groups/G0008/)
- [MITRE ATT&CK G0046 - FIN7](https://attack.mitre.org/groups/G0046/)
