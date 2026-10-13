---
title: "XWorm Malware Research Report"
description: "Evidence-grounded research on XWorm capabilities, observed campaigns, ATT&CK mappings, indicators, detection opportunities, and response."
ms.date: 2026-10-13
ms.topic: reference
estimated_reading_time: 8
keywords:
  - XWorm
  - malware research
  - remote access trojan
  - Windows malware
  - phishing
  - process injection
  - credential theft
  - keylogging
---

## Executive summary

XWorm is a Windows-focused, .NET remote access trojan (RAT), publicly reported since at least 2022. Its modular architecture combines remote control, surveillance, credential theft, and delivery of additional functionality. Commercial availability and reuse by different operators make it a malware family, not an attribution label for a single threat actor.

Published 2025 and 2026 investigations show JavaScript loaders, PowerShell staging, injection into legitimate Windows processes, encrypted command-and-control (C2), and persistence through Startup folders or registry Run keys. The specific loader, host process, infrastructure, and plugins vary between campaigns.

The principal enterprise risks are credential and session compromise, continued remote access, exposure of sensitive information, and execution of additional payloads. A clean-looking signed host process or absence of a standalone malicious executable does not establish that an endpoint is clean.

## Malware profile and evolution

| Attribute        | Research finding                                                                                 |
|------------------|--------------------------------------------------------------------------------------------------|
| Platform         | Windows; analyzed clients are .NET components.                                           |
| Distribution     | Sold in underground ecosystems; deployed by multiple operators.                      |
| Architecture     | Core RAT with additional DLL plugins delivered and executed after infection.             |
| Initial access   | Published campaigns use phishing attachments containing scripts; other delivery paths can vary. |
| Execution        | JavaScript, PowerShell, and injection into legitimate processes appear in recent investigations. |
| Persistence      | Startup-folder artifacts, registry entries, and scheduled tasks appear across analyzed samples. |
| C2               | Configurable infrastructure and encrypted communication; no universal domain or port. |
| Attribution      | Family identification alone does not identify an operator, country, or campaign.                  |

### Observed evolution

1. The 2023 ANY.RUN investigation analyzed a v3.1 sample with obfuscation, environment checks, persistence, and Telegram reporting. Its results are historical sample evidence, not a complete description of current versions.
2. Trellix's October 2, 2025 investigation examined a v6.0 campaign and additional v6-series plugins. It documented JavaScript-to-PowerShell delivery, injection, credential theft, browser-data theft, and registry-backed plugin storage.
3. Gurucul's February 2026 investigation described a v7 chain involving a payment-themed phishing lure, JavaScript persistence, WMI-launched PowerShell, downloaded encoded components, and process hollowing into MSBuild.exe.
4. Trellix's March 12, 2026 investigation examined a v7.1 chain targeting a Taiwan-based network security company. It documented quotation-themed phishing, JavaScript, PowerShell, injection into Aspnet_compiler.exe, registry persistence, and keylog exfiltration.

Version labels are those reported by the researchers. They were not independently verified from binaries. Adoption statistics from sandbox submissions should not be interpreted as population-wide infection counts or market share.

## Capabilities and security impact

### Remote access and additional execution

Trellix and Gurucul describe command execution, file download and execution, process or service management, and remote desktop functionality. Plugins can expand an existing compromise without replacing the core client.

Defender implication: scope investigations beyond the initial payload. Look for later module delivery, secondary payloads, and actions performed under the affected user's security context.

### Credential and browser-data theft

Trellix's v6 research describes plugins that extract credentials from browsers and applications. Additional plugins target browser cookies, passwords, and payment-card data; the research includes browser-process injection and a separate extraction approach in v6.4.

Defender implication: resetting a password alone may not contain an incident involving stolen sessions. Review session revocation, application credentials, and access performed using the compromised identity. These are response recommendations, not proof that every infection stole cookies.

### Surveillance and collection

The v7 analysis describes a low-level keyboard hook, cached keystrokes, screen-capture commands, and user-idle monitoring. The v7.1 investigation reports hidden temporary keylog files and encrypted transmission to C2. Remote desktop and other surveillance capabilities also appear in plugin research.

Defender implication: assess exposure of information typed or displayed during the compromise window, including privileged account use on the infected endpoint.

### Persistence, evasion, and discovery

Published samples use obfuscation, virtual-machine or debugger checks, legitimate host processes, and multiple persistence methods. The 2023 analysis documents scheduled tasks; later investigations document Startup-folder and Run-key persistence.

Injection into a signed process does not make the injected code trustworthy. Similarly, a copied legitimate compiler binary can be an important investigation artifact without its on-disk hash being malicious.

### Disruption and additional impact

DDoS and shutdown or restart commands are documented in the v7 and v7.1 analyses. Gurucul also describes ransomware-related functionality through plugins. These are reported capabilities, not independently confirmed outcomes in the cited victims.

Ransomware preparedness is prudent, but an XWorm alert is not evidence that encryption occurred.

## Campaign-specific infection chains

### Gurucul v7 investigation

1. A payment-confirmation phishing message delivers an archive containing a JavaScript loader.
2. The JavaScript file copies itself into the current user's Startup folder and constructs an obfuscated PowerShell command.
3. WMI launches PowerShell, producing a WmiPrvSE.exe-to-powershell.exe relationship.
4. PowerShell retrieves a JPEG with an appended encoded DLL and a separate text resource containing encoded payload/configuration material. The researcher explicitly distinguishes the appended content from traditional image steganography.
5. The loader uses process hollowing to execute XWorm inside MSBuild.exe.
6. The client establishes encrypted TCP C2 and supports discovery, keylogging, screen capture, and plugin delivery.

The source also describes filesystem writes under Public Downloads. Therefore, the chain should not be characterized as leaving no disk artifacts merely because a payload executes in memory.

### Trellix v7.1 investigation

1. A quotation-themed phishing attachment contains JavaScript executed through wscript.exe.
2. The script downloads a PowerShell stage and stores it under a temporary directory.
3. PowerShell reconstructs payload components and launches Aspnet_compiler.exe, into which a helper DLL injects XWorm.
4. The researcher reports registry Run-key persistence involving a copied, renamed legitimate compiler binary.
5. Keylogging data is stored in a hidden temporary file and sent to the reported C2 destination using an encrypted channel.

These two chains are separate observations. MSBuild.exe and Aspnet_compiler.exe should not be merged into a single mandatory process sequence.

## Architecture and command-and-control

Trellix's v6 analysis describes a registry-backed plugin cache beneath a client-specific key under HKCU\SOFTWARE. Registry value names contain plugin SHA-256 hashes, while value data contains compressed DLL content. Missing plugins can be requested from C2, decoded, and loaded into memory.

Gurucul's v7 analysis reports AES-ECB C2 encryption with a key derived from the MD5 hash of the configured SETTINGS.KEY value. Trellix's v7.1 analysis separately describes AES-protected communication. Do not assume the exact encryption parameters or keys from one sample apply to every version.

Encrypted C2 can limit inspection of payload contents, but it does not eliminate process, destination, timing, persistence, or memory evidence. Ports and destinations in the reports are campaign-specific.

## Evidence-grounded MITRE ATT&CK mapping

Enterprise ATT&CK is appropriate for the documented Windows intrusion behavior. No AI-specific behavior supports an ATLAS mapping. Technique links below were checked against MITRE on the research date.

High confidence means the reported behavior fits the technique definition. It does not mean the behavior was observed in the user's environment. Capability-only entries are identified explicitly.

| Technique and authoritative reference | Relevant tactic       | Reported evidence and qualification                                      | Confidence |
|---------------------------------------|-----------------------|-------------------------------------------------------------------------|------------|
| [T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) | Initial Access | Malicious phishing attachments deliver script loaders. | High |
| [T1059.007: JavaScript](https://attack.mitre.org/techniques/T1059/007/) | Execution | JavaScript/JScript loader execution. | High |
| [T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Execution | PowerShell stages download and reconstruct components. | High |
| [T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) | Execution | WMI launches PowerShell in the Gurucul chain. | High |
| [T1547.001: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) | Persistence | Startup-folder copying and Run-key persistence in separate campaigns. | High |
| [T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | Persistence | Scheduled-task use in the historical sample; not asserted for every recent chain. | High |
| [T1055.012: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/) | Defense Evasion | Explicitly reported hollowing into MSBuild.exe; not inferred for the separate compiler injection. | High |
| [T1056.001: Keylogging](https://attack.mitre.org/techniques/T1056/001/) | Credential Access / Collection | Keyboard-hook capability and reported keystroke collection. | High |
| [T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082/) | Discovery | Host operating-system and hardware profiling. | High |
| [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/) | Collection | Screen-capture command capability; not proof it was used on each victim. | High |
| [T1573.001: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/) | Command and Control | Reported AES-encrypted C2. | High |
| [T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | Command and Control | Downloaded stages and plugin transfer. | High |

Some source mappings were not adopted. TCP alone does not establish an application-layer protocol; in-memory execution alone does not prove indicator removal; idle-time monitoring alone does not establish system-time discovery. DDoS command names alone are insufficient to select a specific denial-of-service sub-technique.

## Selected historical indicators

These indicators are explicitly reported in the cited investigations. "Source-confirmed" means the publisher associated the indicator with its analyzed campaign, not that it was independently validated here or remains malicious today.

No current resolution, ownership, reputation, or infrastructure liveness checks were performed. Start with retrospective correlation. Revalidate indicators before blocking, and do not block entire shared hosting platforms from a single malicious resource.

### Sample hashes

| Type   | Indicator                                                        | Source evidence                              | Status           |
|--------|------------------------------------------------------------------|----------------------------------------------|------------------|
| SHA256 | `de7d74d374a4422c5084280ff71f7942d61f35c271df7d5af01bdd756d0f630b` | JavaScript loader listed in the IOC section. | Source-confirmed |
| SHA256 | `eacd8e95ead3ffe2c225768ef6f85672c4bfdf61655ed697b97f598203ef2cf6` | XWormClient.exe listed in the IOC section. | Source-confirmed |
| SHA256 | `1073FF4689CB536805D2881988B72853B029040F446AF5CED18D1BC08B2266E1` | Analyzed file hash in the historical report. | Source-confirmed |

Hash case is preserved as published. These identify specific files, not all XWorm variants.

### Network indicators

| Type       | Source or defanged representation                  | Normalized value                                 | Evidence and scope                                        |
|------------|-----------------------------------------------------|--------------------------------------------------|-----------------------------------------------------------|
| IPv4       | `158[.]94[.]209[.]180`                               | `158.94.209.180`                                  | Listed as the v7 C2 server.                           |
| IPv4       | `204[.]10[.]160[.]190`                               | `204.10.160.190`                                  | v7.1 C2/exfiltration destination; TCP port 7003 reported. |
| Domain     | `kolanga[.]cc`                                       | `kolanga.cc`                                      | PowerShell-stage delivery host.                       |
| URL        | `hxxps[://]kolanga[.]cc/devils/ENCRYPTEDX[.]ps1`       | `https://kolanga.cc/devils/ENCRYPTEDX.ps1`          | Stage download URL described in the JavaScript analysis. |

Network rows are source-confirmed campaign associations. The domain row is a derived hunting pivot from the explicit URL, not an additional independent observation. Normalized values are for matching, not instructions to visit these resources. The v7.1 IP was also associated with other malware in Trellix's analysis, so a match is not XWorm-specific attribution.

### Behavioral investigation artifacts

* Script files written into the current user's Startup folder.
* Unusual Run-key references to copied or renamed compiler executables under user-writable directories.
* Client-specific registry keys with hash-like value names and compressed binary plugin data.
* Temporary browser-data archives or keylogging files correlated with suspicious execution and outbound traffic.

These are contextual hunting leads, not standalone indicators suitable for indiscriminate blocking. Legitimate MSBuild.exe, Aspnet_compiler.exe, RegSvcs.exe, PowerShell, and WMI should not be globally labeled malicious.

## Detection and hunting opportunities

The following are analyst-derived hypotheses grounded in the cited behavior. No detection rules or queries were executed, and no coverage or false-positive rates are claimed.

### Prioritized investigations

1. Correlate archive-delivered script execution with PowerShell staging. Examine wscript.exe or cscript.exe activity involving recently downloaded files, subsequent downloads, encoded content, and unusual command lines. Administrative scripting is a common benign explanation.
2. Investigate WmiPrvSE.exe launching PowerShell when it is associated with a phishing download, Startup-folder write, or suspicious network destination. Management software can produce this relationship legitimately.
3. Investigate compiler or registration utilities launched by scripting processes and making unexpected external connections. Prioritize corroborating injection telemetry, user-writable copies, or persistence changes; the process name alone is weak evidence.
4. Correlate Startup-folder and Run-key changes with the initiating process, downloaded files, affected account, and subsequent execution. Also review scheduled-task artifacts where historical or local evidence supports them.
5. Examine unusual binary registry data under client-specific HKCU keys, particularly hash-like value names followed by suspicious in-memory activity. Do not treat all large registry values as malware.
6. Hunt the sourced hashes and network indicators over the relevant publication-era windows, then extend searches using related process and file evidence. Historical IP matches require temporal context.
7. Look for browser-process tampering and temporary data archives followed by outbound transfer. Backup, password-management, and security products can produce overlapping behaviors.

### Telemetry requirements and gaps

Useful evidence includes process creation and command lines, parent-child relationships, file and registry changes, PowerShell logging where enabled, endpoint memory/injection signals, DNS and connection records, email attachments, and identity sign-in or session activity.

No particular product table, column, event enum, or parser is assumed. Validate the available schema and retention before writing queries. Ordinary process logs alone may not prove injection or keylogging; absence of those events is not proof those behaviors did not occur.

### Validation criteria before operational deployment

* Confirm that required telemetry is collected and that joins identify the correct device, process, user, and time window.
* Test benign developer, deployment, and endpoint-management workflows alongside authorized representative suspicious activity.
* Measure alert volume, true/false positives, and missing-event behavior before enabling automated response.
* Require corroborating signals for disruptive actions, and preserve an analyst-reviewed exception process.

## Mitigation priorities

1. Reduce delivery exposure through attachment inspection, script-file controls, web filtering, and user reporting. Inspect archives rather than relying only on the outer extension.
2. Restrict unnecessary script execution and use application control where operationally feasible. Pilot changes against business workflows before enforcement.
3. For Microsoft Defender environments, evaluate relevant attack surface reduction rules: blocking JavaScript/VBScript from launching downloaded executable content, potentially obfuscated scripts, executable content from email/webmail, process creation originating from WMI, and copied or impersonated system tools. Check each rule's prerequisites, operating-system support, exclusions, and audit results. These are layered controls, not proven complete XWorm prevention.
4. Maintain endpoint protection, monitoring, and tamper protection. Investigate unexpected protection disablement and prioritize visibility into process injection.
5. Apply least privilege and separate privileged administration from ordinary browsing and email use.
6. Use strong authentication, review risky sessions, and plan session/token revocation when credential or cookie theft is plausible.
7. Restrict unnecessary outbound connectivity and alert on unusual external connections by development utilities.
8. Maintain tested recovery procedures and protected backups for potential follow-on disruptive payloads.

The WMI process-creation ASR rule is distinct from the rule for WMI event-subscription persistence. Select controls for the observed behavior rather than assuming any WMI-related rule covers it.

## Incident response checklist

1. Isolate affected endpoints using the organization's approved process and preserve relevant volatile evidence when feasible.
2. Collect process trees, command lines, persistence artifacts, registry plugin data, memory evidence, attachment details, and network records. Avoid uploading sensitive evidence to public analysis services without authorization.
3. Determine the infection window, initial attachment or URL, affected accounts, and any subsequent payloads or operator actions.
4. Search other endpoints for the same attachment, hashes, temporally relevant infrastructure, and correlated behavioral artifacts.
5. Assess browser-data and keylogging exposure. From clean systems, reset exposed credentials, revoke relevant sessions, and rotate other compromised secrets as appropriate.
6. Remove verified persistence and malicious components. Consider reimaging when remote-control activity, additional payloads, or incomplete visibility prevents confidence in eradication.
7. Validate that suspicious persistence and connections have stopped, review identity activity, and monitor the recovered endpoint before closing the incident.

Deleting the initial script or terminating a host process is not sufficient evidence of eradication.

## References

* [ANY.RUN: XWorm, Technical Analysis of a New Malware Version](https://any.run/cybersecurity-blog/xworm-technical-analysis-of-a-new-malware-version/) (2023). Historical sample analysis, environment checks, persistence, and sample hash.
* [Trellix: XWorm V6, Exploring Pivotal Plugins](https://www.trellix.com/blogs/research/xworm-v6-exploring-pivotal-plugins/) (October 2, 2025). Delivery chain, registry plugin storage, remote control, and credential/browser-data theft.
* [Gurucul: XWorm v7 RAT, Technical Analysis of Infection Chain, C2 Protocol, and Plugin Architecture](https://gurucul.com/blog/xworm-v7-rat-technical-analysis-of-infection-chain-c2-protocol-and-plugin-architecture/) (February 2026). WMI/PowerShell chain, MSBuild hollowing, cryptography, keylogging, and indicators.
* [Trellix: Malware-As-A-Service Redefined, Why XWorm Is Outpacing Every Other RAT in the Underground Malware Market](https://www.trellix.com/blogs/research/malware-as-a-service-redefined-xworm-rat/) (March 12, 2026). v7.1 phishing chain, compiler-process injection, persistence, keylogging, and infrastructure.
* [Microsoft Learn: Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference). Official rule names and deployment/support considerations.
* [MITRE ATT&CK](https://attack.mitre.org/). Authoritative definitions linked individually in the mapping table.
