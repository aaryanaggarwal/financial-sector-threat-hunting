# Suspicious PowerShell Spawned from Office Processes

## Overview

Detects PowerShell processes spawned directly from Microsoft Office applications - a primary initial access pattern in spearphishing campaigns targeting financial sector employees, particularly deal teams, treasury staff, and C-suite assistants.

In financial sector intrusions, threat actors deliver malicious Office documents
via targeted spearphishing. Once opened, the document executes an embedded macro
or exploits a vulnerability to spawn PowerShell for second-stage payload delivery
or C2 beaconing. This behaviour is rarely legitimate in banking environments.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Execution, Initial Access |
| Technique | T1566.001 - Spearphishing Attachment |
| Sub-technique | T1059.001 - PowerShell |
| Chained technique | T1204.002 - Malicious File |
| Relevant threat groups | TA505, Lazarus Group, Cobalt Group, FIN4 |

---

## SPL Query

```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
process_name IN ("powershell.exe", "powershell_ise.exe", "pwsh.exe")
parent_process_name IN ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "eqnedt32.exe")
| eval suspicious_flags=case(
    match(process_cmdline, "(?i)downloadstring|webclient|webrequest"), "download_cradle",
    match(process_cmdline, "(?i)-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b"), "encoded_command",
    match(process_cmdline, "(?i)iex|invoke-expression"), "invoke_expression",
    match(process_cmdline, "(?i)bypass|hidden|noprofile|noninteractive"), "evasion_flags",
    true(), "review_required"
  )
| eval risk_score=case(
    suspicious_flags="download_cradle", 95,
    suspicious_flags="encoded_command", 90,
    suspicious_flags="invoke_expression", 85,
    suspicious_flags="evasion_flags", 80,
    true(), 70
  )
| stats count min(_time) as first_seen max(_time) as last_seen
    values(process_cmdline) as cmdlines
    values(suspicious_flags) as flags by host, user, parent_process_name, process_name, risk_score
| sort - risk_score
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
```

---

## Tuning Notes

**Common false positives in banking environments:**

- Legitimate macros used in finance teams for Excel-based reporting tools.
  Baseline known-good macro-enabled workbooks and exclude by hash or document path:
  `NOT process_cmdline="*\\Finance_Reports\\*"`
- IT automation scripts occasionally spawned via Outlook rules.
  Filter by user OU: exclude IT admin accounts from the alert scope.
- Third-party add-ins (Bloomberg, Refinitiv Eikon) may spawn child processes.
  Build an allowlist of known add-in executables and exclude their process chains.

**Recommended enrichment:**
Join results against your email gateway logs to correlate PowerShell execution
timing with inbound attachment delivery - a match within 10 minutes is high
confidence malicious execution.

---

## Evasion Considerations

Threat actors may attempt to bypass this explicit parent-child relationship using several methods:
* **Indirect Execution:** Spawning an intermediate process (e.g., `cmd.exe`, `wscript.exe`, or `mshta.exe`) from the Office application, which then launches PowerShell.
* **Parent Process Spoofing (T1134.004):** Using API calls (like `UpdateProcThreadAttribute`) to spoof the parent process, making it appear as though `explorer.exe` spawned PowerShell instead of `winword.exe`.
* **Bring Your Own Interpreter:** Dropping a custom script runner instead of relying on the native `powershell.exe`. 

---

## Prevention & Mitigation

Rather than solely relying on detection, organizations can proactively block this behavior using **Microsoft Defender Attack Surface Reduction (ASR) rules**:
* **Rule Name:** Block all Office applications from creating child processes
* **GUID:** `D4F940AB-401B-4EFC-AADC-AD5F3C50588B`

Additionally, configure policies to block VBA macros in files originating from the internet (Mark of the Web).

## Hypothesis

> "If a threat actor is targeting a financial institution via spearphishing, they will deliver a malicious Office document to a finance-role employee (deal team, treasury, C-suite assistant) and use it to spawn PowerShell or PowerShell Core for payload delivery or C2 establishment - betting that macro-enabled documents or legacy equation editor exploits are common enough in banking environments to avoid suspicion."

**Hunt trigger:** Any PowerShell (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`) process with a parent of an Office application (including Word, Excel, PowerPoint, Access, Publisher, or Equation Editor), on any host where the user's role involves access to non-public financial data.

---

## References

- [MITRE ATT&CK T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Cobalt Group TTPs - ESET Research](https://www.eset.com/int/about/newsroom/research/)
- [Microsoft ASR Rules Reference - Block all Office applications from creating child processes](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
