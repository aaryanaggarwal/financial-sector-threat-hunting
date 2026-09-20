# DPRK Financial-Sector Threat Cluster Map (2026)

Reference map for CTI analysts covering financial services and crypto/DeFi.
Purpose: correlate vendor-specific naming to MITRE ATT&CK group IDs so multi-source
feeds don't silently collapse distinct clusters into one "Lazarus" bucket.

## Cluster reference table

| MITRE Group | Vendor aliases | Primary target profile | Primary 2026 initial access | MITRE technique | Notable 2026 activity |
|---|---|---|---|---|---|
| **Lazarus Group (G0032)** | Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY, Diamond Sleet | Broad DPRK umbrella; South Korean financial sector, government, crypto | Drive-by compromise via watering-hole / trojanized sites | T1189 (Drive-by Compromise) | AnySign4PC-linked drive-by campaign against 72+ South Korean financial-sector orgs, active since early 2026 (Rescana, Jul 2026) |
| **BlueNoroff (G0082)** | APT38, NICKEL GLADSTONE, BeagleBoyz, Stardust Chollima, Sapphire Sleet, COPERNICIUM, Black Alicanto, Alluring Pisces, TA444 | Crypto exchanges, DeFi, SWIFT-connected banks | Supply chain compromise | T1195.002 (Compromise Software Supply Chain) | Axios npm package compromise, attributed by Microsoft to Sapphire Sleet, Apr 2026 |
| **UNC1069** (Mandiant; overlaps G0082/Sapphire Sleet) | — | Crypto/DeFi firms, VC firms and their staff | Fake video meeting + malicious paste | T1204.004 (Malicious Copy and Paste / ClickFix) | Fintech intrusion with 7 malware families incl. SILENCELIFT, DEEPBREATH, CHROMEPUSH (Mandiant, Feb 2026) |
| **Contagious Interview (G1052)** | Famous Chollima, DeceptiveDevelopment, Gwisin Gang, Tenacious Pungsan, DEV#POPPER, PurpleBravo, TAG-121, UNC5342, Void Dokkaebi | Software developers; crypto/fintech job seekers | Fake job ads/hiring-site messages, then malicious paste | T1566.003 (Spearphishing via Service) → T1204.004 | BeaverTail / InvisibleFerret / OtterCookie front-company campaign, ongoing 2026 |

**Non-DPRK note:** Gunra ransomware is not itself DPRK-attributed, but AhnLab documented it running parallel campaigns to Lazarus Group against the same South Korean financial-sector targets in 2025–2026, exploiting the same vulnerability in mandatory Korean banking security software and sharing malware filenames, execution arguments, and a common SSH key fingerprint with the Lazarus intrusion set. Track as a shared-access-broker relationship, not a Lazarus subgroup.

## Attribution confidence notes

- MITRE keeps G0032, G0082, and G1052 as **separate** tracked groups. Vendor reporting frequently folds all DPRK financial-motivated activity under "Lazarus" as a colloquial umbrella; MITRE's own G0032 page explicitly flags this naming inconsistency across the industry.
- UNC1069 is a Mandiant-designated cluster, not yet promoted to its own MITRE group ID as of this writing; treat MITRE mapping to G0082 as "overlapping," not identical.
- When ingesting third-party feeds, map vendor names to MITRE group IDs before merging, not after. Microsoft's "Sleet" naming, Mandiant's UNC-numbers, and CrowdStrike's animal names do not have a 1:1 relationship with MITRE groups; several map many-to-one or split further.

## Collection priorities

- Maintain the alias-to-MITRE-ID mapping above as a living table; DPRK clusters rename tooling faster than most feeds relabel it.
- **UNC1069 / BlueNoroff:** monitor EDR command-line telemetry for terminal-paste execution following browser-based meeting-platform pages; flag newly registered domains mimicking Zoom/Teams/Meet.
- **Sapphire Sleet / supply chain:** SBOM coverage and dependency-pinning on any pipeline ingesting npm or other open-source packages, independent of whether the org has direct crypto exposure.
- **Shared-vulnerability pattern:** cross-reference vendor patch cadence for any mandated regional software (e.g., Korean financial security clients) against both espionage and ransomware advisories, not just one or the other.
- **Contagious Interview:** extend phishing-awareness scope to recruiting and HR pipelines; flag "coding assessment" execution occurring outside sanctioned sandboxes.

## Sources
Mandiant/Google Cloud Threat Intelligence (Feb 2026); Microsoft Threat Intelligence (Apr 2026, Axios npm attribution); AhnLab / The Record (Jul 2026, Gunra/Lazarus overlap); Rescana (Jul 2026, AnySign4PC campaign); MITRE ATT&CK groups G0032, G0082, G1052 and techniques T1189, T1195.002, T1204.004, T1566.003.
