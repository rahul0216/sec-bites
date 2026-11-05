---
title: CyberStrikeAI Windows domain compromise threat research
description: Sourced assessment of reported education-sector intrusions, indicators, techniques, and defensive priorities.
ms.date: 2026-11-05
keywords:
  - CyberStrikeAI
  - AI-assisted intrusions
  - LLM orchestration
estimated_reading_time: 10
---

## Executive Summary

Kaspersky reports CyberStrikeAI-assisted intrusions against educational organizations in Africa and Latin America. In the reported setup, a human operator established the foothold and set the objectives. An attacker-side LLM then selected tools and commands for a conventional implant to execute. The public evidence does not show that every action was autonomous, nor does it provide a complete command-by-command audit trail of the control plane.

Kaspersky reports that domain-administrator access was obtained within three to four days of agent deployment. This period followed nearly a day of manual preparation and an approximately two-week pause before deployment. The reporting identifies no initial-access CVE or named threat actor, and confirms no exfiltration volume.


## Reported attack sequence

| Phase                 | Reported evidence                                                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Initial foothold      | Commands originated from `sqlservr.exe` on an already-compromised SQL Server. The original access method remains unknown.             |
| Manual preparation    | Nearly one day of host discovery, tooling deployment, reconnaissance, and credential-related scripting.                              |
| Inactivity            | Approximately two weeks before agent deployment.                                                                                    |
| Agent deployment      | Scheduled-task persistence and local reconnaissance reportedly completed within two minutes.                                        |
| Domain reconnaissance | Approximately five hours of PowerShell and LDAP activity, including information useful for roasting attacks.                          |
| Final activity burst  | After another multi-day pause, SMB/WMI lateral movement, credential dumping, and database export occurred within approximately one hour. |
| Privileged access     | Built-in domain-administrator compromise preceded reported DCSync and Golden Ticket activity.                                        |
| Observed endpoint     | Data collection/export; completed outbound exfiltration was not established.                                                         |

The precise credential transitions and order of all final-stage actions are not public. This sequence is not a fully verified causal graph.

### Credential theft and domain takeover

Reported credential-access behavior included SSRS configuration/DSN extraction and DPAPI-decryption scripting, registry-hive dumping, LSASS dumping through the MiniDump functionality of `comsvcs.dll`, and DCSync using renamed Mimikatz. The public narrative does not provide an unbroken explanation of how the built-in domain administrator's credentials were first obtained.

LDAP reconnaissance useful for Kerberoasting or AS-REP Roasting does not establish successful password cracking. Likewise, DCSync and Golden Ticket activity followed privileged access and should not be represented as the demonstrated original route to administrative control.

### What the AI evidence does and does not show

The reported architecture places the LLM on the attacker's control side, not inside the victim implant. Consequently, absence of victim connections to AI providers does not exclude this activity. Conversely, contacting an AI service does not identify this campaign.

Framework functionality supports the orchestration explanation, but public reporting does not expose model identity, complete prompts, approval history, or command provenance. Claims of lower attacker skill requirements or increased speed are assessments, not controlled comparative measurements.

## Published indicators

The following indicators are associated with samples or infrastructure in Kaspersky's report. Association is not independent validation or proof of present-day malicious ownership. Reassess current ownership and corroborate historical matches before blocking.

### Network indicators

| Defanged indicator       | Published role                                         |
| ------------------------ | ------------------------------------------------------ |
| `185.186.245[.]144`       | Windows beacon C2; reverse-shell connection on port 5501 |
| `fastcdn[.]bar`          | Windows beacon C2                                      |
| `media.fastcdn[.]bar`    | Linux beacon C2                                        |
| `104.234.26[.]163`       | C2/payload delivery and Linux beacon infrastructure     |

Kaspersky describes two sample groups. The public indicator table does not supply a complete group-to-indicator assignment; do not assume one operator or that every indicator belongs to the same Windows intrusion.

### File hashes

All seven values have 32 hexadecimal characters, compatible with MD5 formatting. The source table does not explicitly identify the hash algorithm; confirm it before importing into an algorithm-specific indicator field.

| Hash                               | Published association                                                         |
| ---------------------------------- | ----------------------------------------------------------------------------- |
| `d726a8b4886c636f76ca6d30ef6a6ff4` | Windows beacon, `C:\Windows\Temp\svchosts.exe`                                  |
| `2770562d104391b92b42671c270079bb` | Windows beacon, `svcmon32.exe` under Windows Temp or ProgramData                |
| `09e1da2afa1216ecc55648ec8e122d2a` | Linux beacon                                                                  |
| `805b9e4ae74c903787416800999b8418` | Linux beacon                                                                  |
| `29efd64dd3c7fe1e2b022b7ad73a1ba5` | Renamed Mimikatz, `C:\Windows\Temp\wdiag2.exe`                                  |
| `74f57b3e897a4960dcdd5b7e8a54f9df` | `C:\rwx\RogueWinRM.exe`                                                       |
| `0bbd08af95f877f1d568b03de2eb76b4` | Reverse-shell script, `C:\ProgramData\p1.ps1`                                  |

### Contextual hunting artifacts and exclusions

* Investigate the `SystemUpdate` scheduled task, `d3.b64`, and `C:\ProgramData\dsn_line.txt` in context. Names alone have low specificity.
* `X-Implant-Token` is a framework HTTP-header pivot, not proof of malicious activity or a disclosed secret.
* `rsreportserver.config`, `comsvcs.dll`, `reg.exe`, and GitHub are legitimate resources, not standalone malicious indicators.
* `dnslog[.]cn` is a third-party out-of-band testing service reportedly used for egress discovery. Its use does not justify blanket blocking.
* Do not import IP addresses from detection screenshots without establishing their role; demonstration hosts are not automatically campaign infrastructure.
* HKCU Run-key persistence and Linux cron/`.bashrc` persistence are framework capabilities, not established Windows incident steps.

## MITRE ATT&CK mapping

Mappings describe behavior reported by Kaspersky, not independently verified execution.

| Technique                                                               | Evidence                                                        |
| ----------------------------------------------------------------------- | --------------------------------------------------------------- |
| T1059.001: PowerShell                                                    | Scripted reconnaissance and attacker-directed execution          |
| T1053.005: Scheduled Task                                                | Agent deployment/persistence through scheduled tasks              |
| T1027: Obfuscated Files or Information                                   | Encoded commands and fragmented script content                    |
| T1140: Deobfuscate/Decode Files                                          | Reconstruction and decoding of staged content                    |
| T1552.001: Credentials In Files                                          | SSRS configuration/DSN extraction; medium-confidence fit          |
| T1003: OS Credential Dumping                                             | Registry-hive dumping; specific hives not established             |
| T1003.001: LSASS Memory                                                  | LSASS dump through `comsvcs.dll` MiniDump functionality           |
| T1003.006: DCSync                                                        | Reported replication-based credential theft                      |
| T1558.001: Golden Ticket                                                 | Reported Kerberos ticket forgery following privileged compromise |
| T1078.002: Domain Accounts                                               | Compromised domain accounts used for lateral access              |
| T1021.002: SMB/Admin Shares                                              | Administrative-share lateral movement                            |
| T1047: WMI                                                              | WMI/WMIExec remote execution                                     |
| T1087.002: Domain Account Discovery                                      | LDAP/service-account reconnaissance; medium-confidence fit       |
| T1083: File and Directory Discovery                                      | Recursive share-directory and `.azcopy` discovery                |

Network Share Discovery, T1135, is provisional: recursive enumeration of known shared directories supports T1083 more directly than discovering new shares. No successful roasting, initial-access exploit, or exfiltration technique is assigned without sufficient evidence.

No campaign-specific ATLAS mapping is assigned. Attacker use of an LLM does not, by itself, establish an attack against an AI model, dataset, inference service, prompt boundary, or AI supply chain.

## Defensive priorities

### Detection opportunities

| Priority | Behavior to investigate                     | Telemetry and qualifications                                                                                                              |
| -------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| High     | Unexpected SQL Server child processes       | EDR process ancestry and Security 4688 with command lines; correlate shells/downloaders with SQL authentication and audit records.          |
| High     | Scheduled tasks from writable directories   | Security 4698/4702, Task Scheduler operational logs, and EDR. Include COM-based creation, not only `schtasks.exe`; baseline administration.  |
| High     | LSASS or registry-hive dumping              | EDR process access, dump-file creation, module loading, and configured Sysmon telemetry. Legitimate diagnostics can overlap.                |
| High     | Replication by unexpected principals        | DC Security 4662 with appropriate auditing/SACLs, replication-aware network telemetry, and correlated logons. Review legitimate sync roles. |
| High     | SMB/WMI lateral movement                    | Security 4624/4648/4672 and 5140/5145 where enabled, EDR, and WMI logs; correlate account, source host, remote execution, and staging.         |
| Medium   | Encoded and reconstructed scripts           | PowerShell 4104, AMSI/EDR, 4688, and file events; correlate Base64 fragments, decoding, execution, and network activity.                     |
| Medium   | LDAP reconnaissance followed by ticket use  | LDAP telemetry and DC 4768/4769; distinguish discovery from subsequent ticket acquisition or cracking.                                     |
| Medium   | SSRS secrets and bulk database collection   | EDR, configured file auditing, SQL auditing, configuration access, DSN staging, DPAPI operations, and unusual exports.                      |
| Medium   | Campaign-associated network destinations    | DNS, proxy, firewall, TLS, and EDR network events linked to originating processes. HTTP-header inspection requires content visibility.      |

Security 4662 requires suitable auditing and SACLs; it does not alone identify the network source of replication. Correlate with other records.

Retain enough history to bridge the reported two-week inactivity period and subsequent multi-day gaps. Short execution bursts should be correlated with earlier credential access and discovery. These opportunities have not been tested against a workspace or translated into validated detection coverage.

### Mitigation and response

1. If indicators are corroborated, contain affected systems and preserve endpoint, identity, task, PowerShell, SQL, and network evidence. Removing one beacon is insufficient after privileged credential exposure.
2. Restrict SQL/SSRS administration and network reachability, apply supported updates, minimize service-account privileges, and disable unnecessary OS-command execution features. These controls do not imply that a specific SQL vulnerability was exploited.
3. Use hardened administrative systems, minimize reusable domain credentials on application servers, and deploy supported LSASS protections/Credential Guard. Windows LAPS reduces local-password reuse, not exposure of stolen domain-admin credentials.
4. Restrict SMB/WMI/WinRM and remote task administration to approved management paths. Review directory replication permissions while accommodating authorized identity-sync services.
5. After confirmed DCSync/Golden Ticket exposure, coordinate identity recovery and credential rotation. Plan two `krbtgt` resets after containment, allowing replication and configured ticket lifetimes. Microsoft specifies a default minimum ten-hour interval; adjust to the environment. Two resets alone do not eradicate an active attacker.
6. Validate telemetry collection and test proposed detections in an authorized environment before claiming operational coverage.

## Attribution and campaign boundaries

Chinese-language comments, use of a Chinese DNS service, and restart timing consistent with UTC+8 working hours support only a tentative Chinese-speaking-operator hypothesis. They do not establish nationality, state sponsorship, or a named group. Separate builds and infrastructure do not prove a single operator.

Other CyberStrikeAI reporting must remain separate:

* TrendAI's October 2026 reporting describes 44 agents and at least 19 targeted organizations, including at least 16 in Japan. Its CyberStrikeAI case is not corroboration of this education-sector domain takeover; many attacker-side records explicitly indicated no session, web shell, or exfiltration. Credential and commercial-record theft in TrendAI's separate Case B should not be imported into its CyberStrikeAI Case A.
* Amazon describes Russian-speaking, financially motivated activity against more than 600 FortiGate devices in more than 55 countries during January 11-February 18, 2026. Amazon reports exposed management, weak credentials, and single-factor authentication, not observed exploitation of FortiGate vulnerabilities. Team Cymru subsequently associated CyberStrikeAI with an infrastructure address from that investigation. This does not link that operator to the education-sector intrusions.

## Confidence and remaining gaps

The primary reporting supports CyberStrikeAI involvement and conventional credential theft/lateral movement. Initial access, exact patch state, credential-by-credential progression to domain administrator, degree of autonomy, complete exfiltration, and operator identity remain unresolved.

SQL version `16.0.1000` is consistent with the SQL Server 2022 family; Microsoft lists its full RTM build as `16.0.1000.6`. The truncated reported version is insufficient to identify exact patch level or an exploited flaw.

## References

* [Kaspersky Securelist: CyberStrikeAI attacks educational institutions](https://securelist.com/tr/cyberstrikeai-attacks/121715/). Primary incident research, published November 2, 2026.
* [Cyber Security News: Hackers Use CyberStrikeAI Agents to Automate Windows Domain Takeovers and Credential Theft](https://cybersecuritynews.com/hackers-use-cyberstrikeai-agents-2/). Secondary reporting, published November 2, 2026.
* [TrendAI: Not Only ARTEX](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/not-only-artex-the-different-levels-ai-is-used-in-attacks-targeting-japan). English edition; identifies Japanese original publication as October 23, 2026.
* [Team Cymru: Tracking CyberStrikeAI Usage](https://www.team-cymru.com/post/tracking-cyberstrikeai-usage). Published March 2, 2026; deployment observations January 20-February 26, 2026.
* [Amazon Threat Intelligence: AI-augmented threat actor accesses FortiGate devices at scale](https://aws.amazon.com/blogs/security/ai-augmented-threat-actor-accesses-fortigate-devices-at-scale/). Activity January 11-February 18, 2026; publication date not verified.
* [CyberStrikeAI project](https://github.com/AIPentest/CyberStrikeAI) and [C2 documentation](https://raw.githubusercontent.com/AIPentest/CyberStrikeAI/main/docs/en-US/c2.md). Living documentation accessed November 5, 2026, not pinned incident-era code.
* [Microsoft: SQL Server 2022 build versions](https://support.microsoft.com/en-us/servicing/sql/sql-server-2022/kb5023451-build-versions). Product-version reference.
* [Microsoft: Event 4662 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662). Directory-object auditing reference.
* [Microsoft: Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview). Local administrator password management.
* [Microsoft: AD forest recovery, reset the krbtgt password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password). Recovery sequencing and timing.
