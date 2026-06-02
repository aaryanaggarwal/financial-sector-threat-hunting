# LOLBin Abuse on Finance Workstations

## Overview

Detects living-off-the-land binary (LOLBin) abuse originating from finance-role
workstations, a common pattern in APT intrusions targeting investment banking
environments. Threat actors operating in financial sector networks frequently
avoid custom malware in early intrusion phases, instead abusing legitimate
Windows binaries to blend with normal administrative activity.

This query is particularly relevant for environments where finance workstations
have limited administrative tooling requirements, any LOLBin execution on these
hosts should be treated as anomalous.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Defense Evasion, Execution |
| Technique | T1218 — System Binary Proxy Execution |
| Sub-techniques | T1218.005 (mshta), T1218.010 (regsvr32), T1218.011 (rundll32) |
| Relevant threat groups | TA505, Lazarus Group, FIN7 |

---

## SPL Query

```spl
index=windows sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
(EventCode=1 OR EventCode=4688)
(process_name IN ("mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
                  "wscript.exe", "cscript.exe", "msiexec.exe", "installutil.exe"))
[ search index=asset_inventory asset_role="finance" | fields host ]
| eval risk_score=case(
    process_name="mshta.exe", 90,
    process_name="certutil.exe" AND match(process_cmdline, "urlcache|decode"), 95,
    process_name="regsvr32.exe" AND match(process_cmdline, "http|scrobj"), 90,
    true(), 70
  )
| where risk_score >= 70
| stats count min(_time) as first_seen max(_time) as last_seen
    values(process_cmdline) as cmdlines by host, user, process_name, risk_score
| sort - risk_score
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
```

---

## Tuning Notes

**Common false positives in banking environments:**

- `msiexec.exe` — triggered by legitimate software deployment via SCCM/Intune.
  Add parent process filter: `NOT (parent_process_name="sccm.exe" OR parent_process_name="ccmexec.exe")`
- `certutil.exe` — used by some banking certificate management tools.
  Scope to command-line arguments: only alert when `-urlcache` or `-decode` flags present.
- `rundll32.exe` — frequently noisy. Baseline normal rundll32 invocations per
  host over 30 days and alert only on new/unseen command-line patterns.

**Recommended asset tagging:**
This query assumes an `asset_inventory` lookup with an `asset_role` field.
If unavailable, replace the subsearch with a static host list or OU-based filter
from your AD integration.

---

## Hypothesis

> "If an APT group has achieved initial access in a financial sector environment,
> they will avoid custom tooling in the first 30 days and instead abuse LOLBins
> to establish persistence and move laterally - specifically targeting
> finance-role workstations where credential access yields high-value data."

**Hunt trigger:** Any LOLBin execution on a finance-role workstation with no
corresponding change management ticket or software deployment record.

---

## References

- [MITRE ATT&CK T1218](https://attack.mitre.org/techniques/T1218/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [TA505 TTPs — CISA Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories)
