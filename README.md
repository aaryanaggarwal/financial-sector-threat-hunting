# Financial Sector Threat Hunting

Practical threat hunting resources for financial services environments.
SPL queries, YARA rules, and hunting hypotheses — all MITRE ATT&CK mapped and
documented for SOC teams operating in banking and financial infrastructure.

Built from patterns observed across global Investment and Retail Banking environments.

> All content is generic and sanitised. No client data. No proprietary intelligence.

---

## Contents

| Folder | What's in it |
|---|---|
| `splunk-queries/` | SPL hunting queries mapped to ATT&CK techniques |
| `yara-rules/` | YARA signatures for financial malware families |
| `hunting-hypotheses/` | Structured hypothesis bank for financial sector hunts |
| `detection-coverage/` | ATT&CK coverage maps for banking SOC environments |

---

## How to use this

Each query or rule includes:
- The threat behaviour it targets
- MITRE ATT&CK technique mapping (Tactic → Technique → Sub-technique)
- Why it matters specifically in financial services
- Tuning notes for common banking environment false positives

---

## Contributions

PRs welcome. If you work in financial sector security and have hunting content
to share, open a pull request or raise an issue.

---

## Author

**Aaryan Aggarwal** — Threat Intelligence & Hunting, Deloitte  
[LinkedIn](https://linkedin.com/in/aaryanaggarwal)
