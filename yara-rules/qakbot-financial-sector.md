# YARA Rule: QakBot / QBot Financial Sector Variants

## Overview

QakBot (also known as QBot and Pinkslipbot) is a modular banking trojan active
since 2007, historically one of the most prevalent threats against financial
sector organisations. It functions as both a credential stealer and a loader for
second-stage payloads including Cobalt Strike and ransomware (Black Basta, Conti,
REvil among documented cases).

In August 2023, the FBI-led Operation Duck Hunt dismantled QakBot's C2
infrastructure and removed the malware from over 700,000 compromised machines.
However, QakBot operators were not arrested, and the malware resurfaced in
December 2023 in a new 64-bit variant using AES for C2 communication, delivered
via signed MSI files. As of mid-2024, QakBot-affiliated actors continue to
operate, distributing related malware families via the same phishing
infrastructure.

For financial sector SOC teams: QakBot has been used as initial access for
ransomware attacks against banking institutions, and the same delivery
infrastructure is now being used to distribute DarkGate and PikaBot. Hunting
for QakBot characteristics remains relevant even post-takedown.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1566.001 - Spearphishing Attachment | Delivered via malicious Office docs, ISO+LNK, and post-2023 signed MSI files |
| Defense Evasion | T1027 - Obfuscated Files or Information | RC4-encrypted config in PE resources (pre-2023); AES C2 encryption in post-2023 variants |
| Defense Evasion | T1497.001 - Virtualization/Sandbox Evasion | Checks for `C:\INTERNAL\__empty` to detect Windows Defender sandbox |
| Defense Evasion | T1218.007 - System Binary Proxy Execution: Msiexec | Post-2023 variant executed via signed MSI, invoking the embedded DLL through export `hvsi` |
| Credential Access | T1555 - Credentials from Password Stores | Browser credential harvesting |
| Credential Access | T1056.001 - Input Capture: Keylogging | Documented QakBot capability |
| Lateral Movement | T1021 - Remote Services | Uses stolen credentials for lateral movement |
| Command & Control | T1071.001 - Web Protocols | C2 over HTTP/S; RC4 (pre-2023) and AES (post-2023, `/teorema505` POST path) |

---

## YARA Rules

### Rule 1 - QakBot DLL Loader (Core characteristics)

```yara
import "pe"

rule QakBot_DLL_Loader
{
    meta:
        description     = "Detects QakBot DLL loader - core PE characteristics and anti-sandbox behaviour"
        author          = "Aaryan Aggarwal"
        date            = "2024-06-01"
        tlp             = "WHITE"
        reference       = "https://attack.mitre.org/software/S0650/"
        mitre_attack    = "T1027, T1497.001, T1566.001"
        financial_relevance = "QakBot is a primary initial access vector in ransomware attacks against banking institutions"

    strings:
        $anti_sandbox   = "C:\\INTERNAL\\__empty" ascii wide
        $named_pipe     = "\\\\.\\pipe\\" ascii
        $webinject_cb   = "webinjects.cb" ascii
        $set_url        = "set_url" ascii
        $tmp_pattern    = "%s\\~%s.tmp" ascii
        $c2_format      = "a=%s&b=" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and pe.is_dll()
        and pe.exports("DllRegisterServer")
        and (
            $anti_sandbox
            or (2 of ($webinject_cb, $set_url, $tmp_pattern, $c2_format))
            or ($named_pipe and 1 of ($webinject_cb, $set_url, $c2_format))
        )
}
```

### Rule 2 - QakBot Post-Takedown Variant (December 2023+)

```yara
import "pe"

rule QakBot_PostTakedown_64bit
{
    meta:
        description     = "Detects QakBot post-Duck Hunt resurrection variant (Dec 2023+) - 64-bit AES C2"
        author          = "Aaryan Aggarwal"
        date            = "2024-06-01"
        tlp             = "WHITE"
        reference       = "https://www.darkreading.com/cyberattacks-data-breaches/new-qakbot-sightings-confirm-law-enforcement-takedown-was-temporary-setback"
        mitre_attack    = "T1027, T1566.001, T1218.007"
        financial_relevance = "Post-takedown QakBot delivered via IRS-themed phishing targeting financial sector; same infrastructure now distributes DarkGate and PikaBot"

    strings:
        $anti_sandbox   = "C:\\INTERNAL\\__empty" ascii wide
        $named_pipe     = "\\\\.\\pipe\\" ascii wide
        $c2_path        = "/teorema505" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and pe.machine == pe.MACHINE_AMD64
        and pe.is_dll()
        and pe.exports("hvsi")
        and (
            $anti_sandbox
            or $named_pipe
            or $c2_path
        )
}
```

---

## Tuning Notes

**False positives to expect:**

- Rule 1 `$named_pipe` string is broad on its own - weighted as a supporting
  indicator only, requiring at least one other QakBot-specific string alongside it.
- `DllRegisterServer` export is common across legitimate COM DLLs; the export
  check must be combined with at least two behavioural strings.
- Rule 2 `$c2_path` (`/teorema505`) is campaign-specific to the December 2023
  wave - if operators rotate the URI path in future campaigns, this indicator
  will need updating. Treat it as high-confidence but not evergreen.

**Deployment recommendation:**
Run Rule 1 against file scanning (endpoint EDR, email gateway, sandbox
submissions). Run Rule 2 specifically against MSI files and DLLs extracted
from MSI packages, since the post-2023 variant is MSI-delivered.

**Post-takedown note:**
Even if QakBot itself is not observed, the same phishing infrastructure and
TTPs are now being used to distribute DarkGate and PikaBot. If either is
observed in your environment, treat it as a signal that QakBot-affiliated
actors have access - the delivery chain is the same.

---

## References

- [MITRE ATT&CK S0650 - QakBot](https://attack.mitre.org/software/S0650/)
- [Elastic QBOT V4 Malware Analysis](https://www.elastic.co/security-labs/qbot-malware-analysis)
- [CAPE Sandbox QakBot YARA](https://github.com/ctxis/CAPE/blob/master/data/yara/CAPE/QakBot.yar)
- [FBI Operation Duck Hunt - August 2023](https://www.justice.gov/opa/pr/justice-department-disrupts-prolific-qakbot-malware-and-ransomware-operation)
- [Zscaler ThreatLabz - /teorema505 C2 confirmation](https://x.com/Threatlabz/status/1735863156738871470)
- [The Hacker News - QakBot resurgence, MSI/hvsi delivery](https://thehackernews.com/2023/12/qakbot-malware-resurfaces-with-new.html)
