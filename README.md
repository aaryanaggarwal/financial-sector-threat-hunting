# Financial Sector Threat Hunting and Intelligence

Practical threat hunting and threat intelligence resources for financial services environments.
SPL queries, YARA rules, hunting hypotheses, threat actor playbooks and intelligence profiles,
MITRE ATT&CK mapped and documented for SOC and CTI teams operating in banking and financial infrastructure.

Hunting content is built from patterns observed across global Investment and Retail Banking environments.
Intelligence content is built from public vendor reporting and MITRE ATT&CK, with sources listed in each profile.

> All content is generic and sanitised. No client data. No proprietary intelligence.

---

## Contents

| Folder | What's in it |
|---|---|
| `splunk-queries/` | SPL hunting queries mapped to ATT&CK techniques |
| `yara-rules/` | YARA signatures for financial malware families |
| `hunting-hypotheses/` | Structured hypothesis bank for financial sector hunts |
| `threat-actor-deep-dives/` | Defensive playbooks for threat actors targeting financial services |
| `threat-intel-profiles/` | Intelligence profiles: access paths, aliases, ATT&CK mapping and sources |

---

## How to use this

Each query or rule includes:
- The threat behaviour it targets
- MITRE ATT&CK technique mapping (Tactic → Technique → Sub-technique)
- Why it matters specifically in financial services
- Tuning notes for common banking environment false positives

Each playbook or profile covers:
- The actor or cluster, with aliases across vendors and MITRE
- MITRE ATT&CK technique mapping
- Why it matters specifically in financial services
- Defensive priorities, and for profiles, the sources used

---

## Contributions

PRs welcome. If you work in financial sector security and have hunting or intelligence content
to share, open a pull request or raise an issue.

---

## Author

**Aaryan Aggarwal** - Threat Intelligence & Hunting, Deloitte  
[LinkedIn](https://linkedin.com/in/aaryanaggarwal)
