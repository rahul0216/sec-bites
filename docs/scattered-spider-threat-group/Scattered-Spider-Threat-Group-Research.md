---
title: "Scattered Spider Threat Group Research and Hunting Hypotheses"
description: "Evidence-based profile of Scattered Spider, its identity-led attack flow, campaigns, tools, indicators, and detection opportunities"
author: "rahul0216"
ms.date: 2026-09-18
ms.topic: reference
keywords:
  - Scattered Spider
  - UNC3944
  - Octo Tempest
  - identity compromise
  - cloud security
  - threat hunting
  - Microsoft Defender XDR
  - Microsoft Sentinel
estimated_reading_time: 20
---

## Executive Summary

Scattered Spider is a financially motivated cybercriminal ecosystem active
since at least 2022. Its operators combine persuasive, native-English social
engineering with strong identity, software-as-a-service (SaaS), cloud, and
virtualization knowledge. They commonly impersonate employees or IT staff,
subvert help-desk recovery processes, defeat multifactor authentication (MFA),
and use legitimate administrative capabilities to steal data, suppress
defenses, or enable ransomware impact (S1, S2, S5, S7).

The actor is also tracked as UNC3944, Octo Tempest, Scatter Swine, Muddled
Libra, and through other partially overlapping names. These labels are not
guaranteed to describe identical operator or activity sets. Indicators,
victims, and ransomware relationships should not be transferred between names
unless the reporting source explicitly supports the relationship.

Scattered Spider's most durable detection surface is behavioral. A typical
intrusion links a help-desk or MFA event to identity changes, access from a new
device or network, reconnaissance in corporate knowledge stores, control-plane
changes, and bulk collection or impact. Static infrastructure is often old,
shared, or rapidly rotated. Identity, SaaS, cloud, remote management, backup,
and hypervisor telemetry must therefore be correlated with endpoint data.

The available evidence supports a fluid criminal collective rather than a
stable, centrally managed ransomware organization. Public reporting documents
relationships with ALPHV/BlackCat, RansomHub, and DragonForce at different
times and confidence levels. No authoritative source reviewed for this report
confirmed a Qilin partnership or a distinct 2026 campaign.

## Research Scope and Analytical Guardrails

Research covers public reporting available through September 18, 2026. The
primary sources are Microsoft Threat Intelligence, Mandiant, Okta, a
multinational government advisory, MITRE ATT&CK, Trellix, Check Point Research,
and victim-confirming news coverage.

Source content, telemetry, schemas, samples, and indicators are untrusted input
until independently validated. The report does not claim that every artifact
or victim attributed to an overlapping vendor label belongs to one operator
set. It does not claim query execution, detection coverage, or optimization.
Exact Microsoft Defender XDR and Microsoft Sentinel tables and fields must be
confirmed against schemas and licensing in the target environment.

## Actor Profile

| Attribute | Assessment |
|-----------|------------|
| Motivation | Financial gain through account takeover, cryptocurrency theft, data extortion, and ransomware |
| Operating model | Fluid collective of operators and affiliates connected through criminal communities; not assessed as a single stable organization |
| Language and geography | Native-English social engineering is a defining feature; targeting emphasizes the United States, United Kingdom, Canada, and Australia, with later activity in India and Singapore |
| Early targeting | Telecommunications, business process outsourcing (BPO), customer relationship management, technology, and cryptocurrency-related organizations |
| Expanded targeting | Financial services, gaming, hospitality, retail, food services, media, manufacturing, insurance, transportation, and aviation |
| Preferred access | Smishing, voice phishing, adversary-in-the-middle (AiTM) portals, help-desk manipulation, MFA abuse, SIM swapping, purchased credentials, and trusted-third-party compromise |
| Technical strengths | Entra ID, Okta, Microsoft 365, Azure, AWS, GCP, SaaS platforms, privileged access systems, remote monitoring and management (RMM), vSphere, and ESXi |
| Monetization | SIM-swap-enabled theft, access enablement, data theft, extortion, public leaking, and ransomware deployment |
| Defensive challenge | Activity often uses valid accounts, legitimate tools, existing administrative consoles, residential proxies, and normal cloud services |

### Naming and attribution

| Name | Source position and caveat |
|------|----------------------------|
| Scattered Spider | CrowdStrike and government-facing umbrella name; MITRE group G1015 |
| UNC3944 | Mandiant cluster described as overlapping significantly with Scattered Spider |
| Octo Tempest | Microsoft cluster overlapping Scattered Spider, UNC3944, and 0ktapus |
| Scatter Swine | Okta name for a 2022 phishing cluster later associated with overlapping activity |
| Muddled Libra | Unit 42 cluster commonly treated as overlapping; direct taxonomy was not independently verified from an accessible primary page during this research |
| 0ktapus or Roasted 0ktapus | Related phishing activity associated by MITRE and vendors |
| Storm-0875 or DEV-0875 | Historical Microsoft naming associated with Octo Tempest |

Arrests and disruption can affect individual operators without eliminating the
broader ecosystem. Actor attribution should therefore be stored separately
from technical confidence and victim-confirmed impact.

## Campaign and Tradecraft Timeline

| Period | Activity | Evidence and caveat |
|--------|----------|---------------------|
| 2021 to mid-2022 | UNC3944 used the EIGHTBAIT phishing kit, collected credentials through Telegram, and optionally deployed AnyDesk | Observed by Mandiant (S2) |
| August 2022 | The Twilio incident exposed information associated with 163 customers; Okta linked Scatter Swine activity to searches for phone numbers and SMS one-time passwords | Observed by Okta; the downstream scope varied by customer (S8) |
| 2022 | Telecom and BPO access supported SIM swaps, account takeover, cryptocurrency theft, and secondary operations | Observed across Microsoft, Mandiant, and government reporting (S1, S2, S7) |
| Late 2022 to early 2023 | Targeting expanded to cable, email, and technology organizations; data theft and extortion became more prominent | Observed (S1, S11) |
| 2023 | STONESTOP and POORTRY were used in bring-your-own-vulnerable-driver activity to interfere with endpoint security | Observed; CVE-2015-2291 featured in reporting (S1, S11) |
| Mid-2023 | Microsoft assessed Octo Tempest became an ALPHV/BlackCat affiliate and progressed from data-only extortion to Windows and Linux ransomware, including ESXi targeting | Observed by Microsoft (S1) |
| September 2023 | MGM Resorts and Caesars publicly confirmed material incidents; security reporting associated the incidents with Scattered Spider methods and ALPHV | Reported attribution; victim confirmation does not independently prove the complete actor taxonomy |
| 2023 to 2024 | Activity expanded into Entra ID, Azure, Okta, AWS, GCP, Salesforce, CyberArk, CrowdStrike, Workday, SharePoint, Snowflake, backup systems, and vSphere | Observed by Microsoft and Mandiant (S1, S2, S3, S4) |
| Since early 2024 | Mandiant investigations emphasized SaaS theft and extortion and did not observe ransomware deployment in that UNC3944 case set | Observed; does not prove all overlapping activity abandoned ransomware (S3) |
| 2024 | Mandiant reported sector-focused waves, including food services, and identified UNC3944 as a RansomHub affiliate after ALPHV shut down | Observed by Mandiant (S5) |
| April to May 2025 | Co-op confirmed member-data theft; actors using the DragonForce name claimed attacks against Co-op, M&S, and Harrods | Victim impact and criminal claims are confirmed separately; UNC3944 involvement remained unconfirmed by Mandiant at publication (S5, S13) |
| Mid-2025 | Government and Mandiant reporting described retail, airline, transportation, and insurance targeting and an identity-to-vSphere ransomware playbook | Observed and reported (S6, S7) |
| July 2025 | The multinational advisory added layered vishing, purchased credentials, third-party compromise, RattyRAT, Snowflake mass querying, fake identity support, proxy rotation, and DragonForce ESXi encryption | Observed or reported by participating authorities (S7) |
| Through September 2026 | MITRE continued to document BlackCat and DragonForce behaviors; no reviewed authoritative source established a separate 2026 campaign or Qilin partnership | Assessed from current source set (S10) |

## Infection and Attack Flow

| Stage | Behavior | High-value observables |
|-------|----------|------------------------|
| Target development | Collect employee roles, phone numbers, leaked personal data, help-desk procedures, suppliers, and authentication details | Lookalike domain registration, employee-focused reconnaissance, repeated support-process questions |
| Initial access | Use smishing, AiTM portals, voice phishing, MFA fatigue, SIM swaps, purchased credentials or tokens, compromised contractors, and help-desk password or MFA resets | Reset ticket, factor reset, new device, new IP, successful sign-in, external collaboration contact |
| Execution and foothold | Install RMM, use cloud consoles, create VMs, or operate directly through SaaS and identity control planes | New RMM tenant, remote response session, public VM, unusual cloud shell or serial-console use |
| Identity persistence | Register MFA methods and devices, create identities or service principals, add cloud credentials or roles, establish federation or Okta Org2Org, and alter trusted locations | Authentication-method change, device registration, app credential, role grant, domain federation, policy exclusion |
| Discovery | Search SharePoint, Delve, wikis, source repositories, password vaults, cloud inventories, AD, PAM, backup systems, and vSphere groups | High-volume search, sensitive-site access, account and group enumeration, secret-scanner execution |
| Privilege escalation | Impersonate administrators or extract credentials from Vault, CyberArk, source code, files, NTDS.dit, cloud secret stores, and virtual disks | Vault access, privileged reset, VMDK reattachment, directory database access, role escalation |
| Lateral movement | Use valid accounts, RDP, SSH, WMI, Impacket, WinRM, cloud serial console, Intune, EDR response consoles, RMM, vCenter, proxies, and tunnels | New remote logon path, management-console script, tunnel process, vCenter group change |
| Collection | Gather email, SharePoint, Salesforce, Snowflake, databases, repositories, cloud storage, credentials, and PAM data | Bulk query or download, novel user agent, unusual export job, sensitive dataset access |
| Staging and exfiltration | Use Airbyte, Fivetran, Azure Data Factory, backup products, Rclone, MEGA, S3, SFTP, and file-hosting services | New connector, external destination, archive staging, high-volume transfer, backup registration |
| Defense evasion | Disable Defender or telemetry, alter EDR allowlists, use unmanaged VMs, hide security email, rotate proxies, and monitor incident-response chats | Security setting change, mailbox rule, log gap, unmanaged source, incident-channel access |
| Impact | Steal cryptocurrency, extort victims, leak data, delete backups, or deploy BlackCat or DragonForce against Windows, Linux, and ESXi | Backup deletion, mass VM shutdown, ESXi security change, unsigned encryptor, ransom activity |

### Identity-led initial access

The actor frequently turns a support workflow into an authentication event.
Operators use personal information and internal terminology to persuade a help
desk to reset a password, replace an MFA method, or register a device. Other
operations use SMS phishing, AiTM pages, repeated MFA prompts, or purchased
session material. A single sign-in from a residential or VPN address is weak
evidence. A reset followed by factor registration and sensitive access is much
stronger.

### Cloud and SaaS persistence

Compromised identity administrators can create access paths that survive a
password reset. Documented mechanisms include additional MFA methods, rogue
devices, service-principal credentials, privileged role assignments, new
federated domains, Golden SAML, Okta Org2Org relationships, newly created
identities, and Conditional Access trusted-location changes (S1, S3, S4, S9).

New public cloud VMs may act as unmanaged internal attack platforms. Existing
instances, serial consoles, VMAccess, Intune, and EDR response consoles can
provide execution without a conventional malware delivery chain. Recovery
must therefore examine the identity and control planes, not only endpoints.

### Knowledge discovery and privilege escalation

Operators search corporate knowledge systems for VPN instructions, network
diagrams, onboarding documents, security procedures, administrator names, and
incident-response communications. Source repositories and secret stores can
yield service credentials. PAM systems, directory databases, cloud secrets,
and detached virtual disks can provide higher privilege.

This sequence creates a useful correlation: newly recovered or risky identity,
unusual access to internal documentation, secret or role discovery, and a
privileged change. Each event can be legitimate in isolation.

### Virtualization, backup, and ransomware impact

Mandiant documented an identity-to-vSphere playbook in which attackers reached
vCenter, manipulated administrator groups, enabled remote access, used
Teleport, powered down systems, attached sensitive VMDKs to other VMs, damaged
backup capability, and encrypted ESXi datastores (S6). Hypervisor and backup
telemetry is essential because endpoint agents may not observe these actions.

The actor's ransomware relationships changed over time. Microsoft directly
reported an ALPHV/BlackCat affiliate relationship. Mandiant reported a
RansomHub relationship. DragonForce deployment is supported by multinational
government reporting and 2025 campaign evidence. These relationships should
be treated as time-bound, not permanent actor identity.

## Tools and Services

### Remote access and tunneling

| Category | Tools or services | Reported use |
|----------|-------------------|--------------|
| RMM and remote desktop | AnyDesk, ScreenConnect, FleetDeck, Level.io, Pulseway, Splashtop, TacticalRMM, RustDesk, TeamViewer, TightVNC, RemotePC, Chrome Remote Desktop | Establish interactive access through legitimate signed software |
| Overlay networks and tunnels | Tailscale, Twingate, Teleport, ngrok, Cloudflare Tunnel, Localtonet, rsocx, wstunnel | Reach internal services, preserve access, or move data |
| Native remote services | RDP, SSH, WinRM, WMI, Azure serial console, vCenter console | Administer endpoints, cloud systems, and hypervisors using built-in capabilities |

Tool presence alone does not establish compromise. Hunt for unauthorized
product, tenant, installer source, operator account, destination, persistence,
or use outside an approved support window.

### Discovery, credential, and administration tools

| Purpose | Tools or capabilities |
|---------|-----------------------|
| Directory and cloud discovery | ADRecon, ADExplorer, PingCastle, SharpHound, Advanced IP Scanner, MicroBurst, AADInternals |
| Credential and secret access | Mimikatz, LaZagne, Hekatomb, TruffleHog, GitGuardian, psPAS, HashiCorp Vault client, PCUnlocker |
| Remote execution and administration | Impacket, PowerShell, Intune, EDR remote response, PowerCLI, Azure Storage Explorer |
| Collection and transfer | Rclone, Airbyte, Fivetran, Azure Data Factory, cloud storage, SFTP, file-hosting services |
| Virtualization and impact | vCenter, ESXi SSH, `vim-cmd`, VMDK attachment, BlackCat, DragonForce |

### Malware and criminal tooling

Reported malware includes EIGHTBAIT, RECORDSTEALER, ULTRAKNOT or Meduza,
VIDAR, ATOMIC, Raccoon Stealer, WarZone or AveMaria, RattyRAT, LummaC2,
Bedevil, POORTRY, STONESTOP, BlackCat, and DragonForce (S1, S2, S7, S11).
Occurrence varies by vendor cluster and period. A malware family linked to one
operation should not automatically be attributed to every Scattered Spider
intrusion.

## Indicators of Compromise

The following indicators are historical source-confirmed or source-reported
examples. They are hunting pivots, not a current blocklist. Defanged network
values must remain defanged in documentation and should be normalized only in
an approved enrichment or hunting workflow.

### File hashes

| SHA-256 | Context | Confidence |
|---------|---------|------------|
| `3ea2d190879c8933363b222c686009b81ba8af9eb6ae3696d2f420e187467f08` | Packed FleetDeck binary reported by Trellix on August 17, 2023 | Medium; old and associated with legitimate RMM |
| `cce5e2ccb9836e780c6aa075ef8c0aeb8fec61f21bbef9e01bdee025d2892005` | `IIatZ` backconnect TCP malware used after OpenAM exploitation | High for the reported sample |
| `acadf15ec363fe3cc373091cbe879e64f935139363a8e8df18fd9e59317cc918` | `insomnia.exe` API debugging utility | Medium; dual use |
| `982dda5eec52dd54ff6b0b04fd9ba8f4c566534b78f6a46dada624af0316044e` | `lockhuntersetup_3-4-3.exe` file-unlocking utility | Medium; dual use |
| `443dc750c35afc136bfea6db9b5ccbdb6adb63d3585533c0cf55271eddf29f58` | `mpbec` packed backconnect binary | High for the reported sample |

### Network indicators

| Type | Defanged value | Context | Confidence |
|------|----------------|---------|------------|
| IPv4 | `67[.]43[.]235[.]122` | `mpbec` destination on TCP 4444 or 8888 | Medium; stale |
| IPv4 | `136[.]144[.]19[.]51` | Reported MFA registration source | Medium; stale |
| IPv4 | `134[.]209[.]48[.]68` | Reported adversary remote access | Medium; stale cloud address |
| IPv4 | `142[.]93[.]229[.]86` | Reported adversary remote access | Medium; stale cloud address |
| IPv4 | `144[.]76[.]136[.]153` | Associated with `transfer.sh` exfiltration | Low to medium; shared service |
| IPv6 | `2a01:4f8:200:1097::2` | Associated with `transfer.sh` exfiltration | Low to medium; stale and shared |
| IPv4 | `185[.]56[.]83[.]225` | Okta cross-tenant impersonation cluster, July to August 2023 | Medium; broader actor overlap not proven by Okta |
| IPv4 | `96[.]244[.]225[.]43` | Same Okta cluster | Medium to low; likely residential |
| IPv4 | `24[.]189[.]245[.]79` | Same Okta cluster | Medium to low; likely residential |
| URL | `hxxps://agent[.]fleetdeck[.]io/HiZGDaf5T3xTLZdBWUsG2Q?win` | FleetDeck download command executed through EDR remote response | Medium; legitimate service and mutable token |

### Candidate phishing domains

| Defanged domain | Context | Confidence |
|-----------------|---------|------------|
| `chipotle-sso[.]com` | Domain matching a reported organization-themed targeting pattern | Low to medium; not all candidates were confirmed malicious |
| `gemini-servicedesk[.]com` | Domain matching a service-desk impersonation pattern | Low to medium |
| `hubspot-okta[.]com` | Domain matching an identity-provider impersonation pattern | Low to medium |

### Host and cloud artifacts

| Artifact | Context | Confidence |
|----------|---------|------------|
| `PCUnlocker.iso` | Mounted through vCenter to reset local administrator passwords | Medium; legitimate recovery product |
| `/etc/teleport.yaml` | Teleport configuration on a compromised vCenter Server Appliance | Medium when unauthorized |
| `/lib/systemd/system/teleport.service` | Teleport persistence on a vCenter Server Appliance | Medium when unauthorized |
| `encrypt.out`, `encrypt_.out`, `list.txt` | ESXi ransomware payload, copy, and exclusion-list names in a documented playbook | Medium; mutable names |
| New federated domain or IdP with automatic account linking | Golden SAML or Org2Org impersonation persistence | High behavioral confidence |
| New public Azure VM without mandated EDR or logging | Internal attack platform and persistence | High behavioral confidence |
| Azure Data Factory pipeline changed to external SFTP | High-bandwidth data theft path | High behavioral confidence |
| Airbyte or Fivetran connector sending SaaS data to external S3 | Automated SaaS exfiltration | High behavioral confidence |

No source-confirmed malicious email address, account name, or malicious
registry path was retained. A defensive registry configuration mentioned in
source reporting is not an actor IOC.

## Indicators of Attack and Detection Opportunities

| Behavior chain | Required visibility | Why it matters | Common benign explanation |
|----------------|---------------------|----------------|---------------------------|
| Help-desk reset, MFA registration, then new-device sign-in | Ticketing, Entra or IdP audit, authentication logs | Captures the actor's preferred social-engineering-to-identity transition | Lost phone, new employee, legitimate recovery |
| MFA challenge burst followed by success | MFA and sign-in logs | May reveal fatigue or operator-guided approval | User retries or network delay |
| External identity impersonates support through Teams | Teams and M365 audit | Extends voice and SMS pretexting into collaboration platforms | Approved vendor support |
| Risky sign-in followed by SharePoint, email, or admin access | Identity risk, M365, SaaS, and cloud audit | Links access to discovery or collection | Travel, VDI, approved automation |
| New federation, IdP, service-principal secret, or cloud role | Entra, Okta, Graph, and cloud audit | Detects durable identity persistence | Application rollout, merger, emergency change |
| New public VM without standard controls | Azure activity, inventory, Defender for Cloud | Detects an unmanaged attack platform | Development or testing workload |
| Knowledge-store search followed by bulk download | SharePoint, M365, CASB, proxy | Identifies discovery-to-collection progression | Migration, eDiscovery, backup |
| Secret scanner followed by vault or repository access | Endpoint process, source control, PAM | Connects tool execution to credential access | Authorized security assessment |
| Unsanctioned RMM or tunnel with persistent egress | Endpoint, DNS, proxy, network, software inventory | Detects legitimate-tool abuse | Approved support tooling |
| EDR or device-management console deploys scripts unusually | Console audit, cloud app audit, endpoint events | Detects abuse of trusted execution channels | Emergency response or software rollout |
| vSphere role change followed by appliance or ESXi access | AD, vCenter, VCSA, ESXi, network flow | Captures identity-to-hypervisor movement | Planned maintenance |
| VMDK attached to an unrelated VM after power-off | vCenter and ESXi events | May expose credentials or sensitive data without endpoint execution | Recovery or forensics |
| Backup access followed by deletion | AD, Windows logon, backup audit | Detects recovery inhibition before ransomware | Retention maintenance |
| New ETL connector to external storage | SaaS, ETL, cloud storage, Azure activity | Identifies native-service exfiltration | Approved analytics or migration |
| Security-message deletion or hiding rules | Exchange and M365 audit | Detects suppression of alerts and response communications | User mailbox cleanup |
| ESXi SSH, mass shutdown, security change, or unsigned execution | ESXi and vCenter audit, network flow | Detects imminent hypervisor impact | Emergency maintenance |

## MITRE ATT&CK Mapping

Mappings use the current MITRE Scattered Spider G1015 page, last modified July
31, 2026, and the multinational advisory's ATT&CK v17 mappings. Each technique
is tied to behavior in the reviewed source set.

| ID | Technique | Confidence | Behavioral rationale |
|----|-----------|------------|----------------------|
| T1589 | Gather Victim Identity Information | High | Collects employee identity, role, phone, and leaked personal information for impersonation |
| T1598.004 | Phishing for Information: Spearphishing Voice | High | Calls employees and help desks to learn reset processes or obtain information |
| T1583.001 | Acquire Infrastructure: Domains | High | Registers organization-themed SSO, Okta, VPN, and help-desk domains |
| T1566.004 | Phishing: Spearphishing Voice | High | Vishing induces password or MFA resets and remote-tool execution |
| T1199 | Trusted Relationship | High | Abuses outsourced IT, BPO, help-desk, and contractor access |
| T1078.002 | Valid Accounts: Domain Accounts | High | Uses reset, purchased, or stolen enterprise credentials |
| T1078.004 | Valid Accounts: Cloud Accounts | High | Uses compromised Entra, Okta-federated, AWS, and SaaS identities |
| T1621 | Multi-Factor Authentication Request Generation | High | Repeated push notifications attempt to induce approval |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | High | Registers attacker-controlled authenticators and resets existing methods |
| T1539 | Steal Web Session Cookie | High | Infostealers and AiTM activity capture browser or session material |
| T1484.002 | Domain or Tenant Policy Modification: Trust Modification | High | Adds federated domains or inbound identity providers for impersonation |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | High | Adds credentials or temporary federated credentials |
| T1098.003 | Account Manipulation: Additional Cloud Roles | High | Assigns privileged cloud roles |
| T1098.005 | Account Manipulation: Device Registration | High | Registers devices to preserve MFA or VPN access |
| T1136 | Create Account | High | Creates identities, sometimes supported by fake social profiles |
| T1578.002 | Modify Cloud Compute Infrastructure: Create Cloud Instance | High | Creates cloud VMs as unmonitored attack platforms |
| T1219.002 | Remote Access Tools: Remote Desktop Software | High | Deploys AnyDesk, ScreenConnect, FleetDeck, and other RMM software |
| T1572 | Protocol Tunneling | High | Uses Teleport, ngrok, rsocx, wstunnel, and overlay networks |
| T1087.004 | Account Discovery: Cloud Account | High | Enumerates Entra and cloud users |
| T1069.003 | Permission Groups Discovery: Cloud Groups | High | Enumerates cloud groups, roles, and privileged users |
| T1580 | Cloud Infrastructure Discovery | High | Enumerates cloud resources, storage, databases, and backups |
| T1213.002 | Data from Information Repositories: SharePoint | High | Searches internal documentation for access and architecture information |
| T1213.003 | Data from Information Repositories: Code Repositories | High | Searches source repositories for secrets and signing material |
| T1213.005 | Data from Information Repositories: Messaging Applications | High | Monitors Teams and Slack for incident-response activity |
| T1555.005 | Credentials from Password Stores: Password Managers | High | Targets HashiCorp Vault, CyberArk, and PAM systems |
| T1552.001 | Unsecured Credentials: Credentials in Files | High | Searches documents, shares, and repositories for credentials |
| T1003.003 | OS Credential Dumping: NTDS | High | Extracts `NTDS.dit`, including through virtual-disk manipulation |
| T1021.007 | Remote Services: Cloud Services | High | Uses cloud instances and cloud management paths for lateral movement |
| T1047 | Windows Management Instrumentation | High | Uses WMI and Impacket for remote execution |
| T1564.008 | Hide Artifacts: Email Hiding Rules | High | Creates rules that delete or conceal security notifications |
| T1685 | Disable or Modify Tools | High | Disables EDR, Defender, telemetry, firewall, and other controls |
| T1074 | Data Staged | High | Consolidates data before exfiltration, including through ETL systems |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | High | Transfers data to MEGA, S3, GCP, and file-sharing services |
| T1041 | Exfiltration Over C2 Channel | Medium to high | Teleport has been used to move data from compromised vCenter infrastructure |
| T1490 | Inhibit System Recovery | High | Deletes backups, repositories, snapshots, or recovery capabilities |
| T1486 | Data Encrypted for Impact | High | Deploys BlackCat and reportedly DragonForce, including against ESXi |
| T1657 | Financial Theft | High | Monetizes access through cryptocurrency theft, extortion, and ransomware |

SIM swapping is represented in ATT&CK Mobile as T1451, not ATT&CK Enterprise.
It remains operationally important but is not included in the Enterprise table.

## Prioritized Hunting Hypotheses

These hypotheses are designed for translation into environment-specific KQL.
Table names are likely data families, not a guarantee that the needed event or
field exists in every tenant. Confirm schemas, connectors, retention, and
normal behavior before implementation.

### Hypothesis 1: Help-desk recovery leads to identity takeover

* Hypothesis: An attacker convinces support to reset a password or MFA method,
  then signs in from a new device or network.
* Telemetry: Help-desk tickets, Windows security event 4724, Entra `AuditLogs`,
  `SigninLogs`, and Defender XDR `AADSignInEventsBeta` where available
* Logic: Correlate reset or authentication-method change with device
  registration and successful sign-in for the same user within 30 to 60
  minutes.
* Pivots: User, support agent, source IP, device ID, authentication method,
  ticket ID
* False positives: Lost device, new employee, or approved account recovery
* Validation: Confirm callback evidence, ticket approval, device ownership,
  and whether phishing-resistant MFA was restored.

### Hypothesis 2: MFA fatigue precedes successful authentication

* Hypothesis: Repeated challenges or one-time-password sends cause the user to
  approve an attacker session.
* Telemetry: Entra sign-ins, IdP MFA logs, Okta System Log, and `OktaSSO` where
  connected
* Logic: Count failed, denied, timed-out, or repeated prompts followed by a
  success for one user within 15 to 30 minutes.
* Pivots: User, IP, device, session, application, authentication detail
* False positives: User retries, network delay, or authenticator migration
* Validation: Check number matching, user report, sign-in risk, device
  compliance, and post-authentication activity.

### Hypothesis 3: External collaboration identity impersonates IT support

* Hypothesis: An external Teams identity resembling the help desk contacts
  employees before account or device changes.
* Telemetry: Teams and M365 audit, `CloudAppEvents`, `OfficeActivity`, help-desk
  tickets, and identity audit
* Logic: Find new external tenants or identities with support-themed display
  names contacting multiple users, then correlate identity changes within 24
  hours.
* Pivots: External tenant, display name, sender, recipient, URL, affected user
* False positives: Approved suppliers and outsourced support
* Validation: Verify supplier domain, contract, support engagement, and message
  content through approved investigative handling.

### Hypothesis 4: New-session access progresses into M365 discovery

* Hypothesis: A stolen session or new-device sign-in is used to search internal
  knowledge and reach sensitive SaaS data.
* Telemetry: Entra risk and sign-ins, `CloudAppEvents`, `OfficeActivity`,
  SharePoint, Exchange, and proxy or CASB data
* Logic: Correlate a risky or novel sign-in with high-volume search, sensitive
  site access, or bulk download within one to four hours without fresh MFA.
* Pivots: User, session, IP, device, user agent, site, file
* False positives: Travel, VDI, eDiscovery, migration, or backup activity
* Validation: Compare device compliance, token issuance, user baseline,
  application identity, and download volume.

### Hypothesis 5: Privileged sign-in creates durable identity persistence

* Hypothesis: A compromised administrator creates federation, an identity
  provider, a service-principal credential, or a new trust relationship.
* Telemetry: Entra `AuditLogs`, Graph audit, service-principal sign-ins, Okta
  System Log, and identity configuration history
* Logic: Detect a new or changed domain, federation configuration, inbound IdP,
  Org2Org relationship, application credential, or automatic account-linking
  setting after a novel privileged sign-in within 24 hours.
* Pivots: Actor, target domain or application, IP, device, changed property
* False positives: Application rollout, merger, or planned federation change
* Validation: Require a change record, second-admin approval, credential owner,
  and review of all identities authenticating through the new trust.

### Hypothesis 6: Factor reset enables Okta administrator impersonation

* Hypothesis: An attacker resets an Okta factor, reaches Super Admin through a
  proxy, and adds or modifies an identity provider.
* Telemetry: Okta System Log and help-desk or administrator audit
* Logic: Correlate factor reset with a new-network administrator session and
  IdP, Org2Org, account-linking, or role change within one hour.
* Pivots: Administrator, IP, device, factor, IdP, target tenant
* False positives: Legitimate recovery or merger integration
* Validation: Confirm dual approval, known administrator device, proxy
  ownership, and expected IdP metadata.

### Hypothesis 7: An unmanaged cloud VM becomes an attack platform

* Hypothesis: A compromised cloud administrator creates or reactivates a public
  VM that lacks required security controls.
* Telemetry: `AzureActivity`, Azure Resource Graph, Defender for Cloud,
  `DeviceInfo`, network security changes, and cloud inventory
* Logic: Find new or reactivated VMs with public exposure, unusual creator or
  deployment path, and no expected EDR, logging, naming, image, or tags within
  six to 24 hours.
* Pivots: Creator, subscription, resource group, VM, public IP, image
* False positives: Development, testing, disaster recovery, or red-team work
* Validation: Confirm infrastructure-as-code lineage, owner, change record,
  image provenance, agent state, and subsequent internal connections.

### Hypothesis 8: Cloud policy or role change weakens access controls

* Hypothesis: The actor assigns privilege, elevates access, changes a trusted
  location, or excludes an identity from MFA policy.
* Telemetry: Entra and Azure audit, `AzureActivity`, PIM, Conditional Access
  configuration, and identity protection
* Logic: Detect anomalous role assignment, Elevate Access, named-location
  change, authentication policy change, or exclusion after a risky sign-in
  within one to four hours.
* Pivots: Actor, target user or service principal, role, scope, policy, IP
* False positives: Emergency administration or planned policy maintenance
* Validation: Confirm approved incident or change, PIM activation, break-glass
  procedure, and scope of affected identities.

### Hypothesis 9: Knowledge discovery transitions to bulk collection

* Hypothesis: The actor searches SharePoint, Delve, email, or internal wikis for
  access and architecture information before downloading data.
* Telemetry: `OfficeActivity`, `CloudAppEvents`, SharePoint audit, proxy, and
  CASB
* Logic: Identify unusual search terms, sensitive-site traversal, or broad
  enumeration followed by bulk or novel-user-agent download within six to 24
  hours.
* Pivots: User, site, file, search term where available, IP, user agent
* False positives: eDiscovery, migration, legal review, or backup
* Validation: Compare user role, normal sites, application, volume, session,
  and destination.

### Hypothesis 10: Secret discovery tools precede privileged access

* Hypothesis: TruffleHog, GitGuardian, AADInternals, SharpHound, or similar tools
  identify credentials that are then used against repositories or PAM.
* Telemetry: `DeviceProcessEvents`, `DeviceFileEvents`, source-control audit,
  PAM logs, EDR alerts, and command-line telemetry
* Logic: Correlate tool execution or characteristic command lines with new
  repository, vault, or privileged account access within four hours.
* Pivots: Device, user, process tree, repository, secret, vault, target account
* False positives: Authorized security scanning or engineering workflows
* Validation: Confirm sanctioned scanner host, operator, ticket, expected
  repository scope, and whether exposed secrets were used.

### Hypothesis 11: Unsanctioned RMM or tunnel preserves access

* Hypothesis: The actor installs a legitimate RMM, overlay network, or tunnel
  and establishes persistent outbound connectivity.
* Telemetry: `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceInfo`,
  software inventory, DNS, proxy, and firewall data
* Logic: Detect first-seen RMM or tunnel installation, service or startup
  persistence, and connections to an unapproved tenant or destination within
  24 hours.
* Pivots: Device, signer, hash, installer source, service, domain, account,
  tenant identifier
* False positives: IT support, remote work, developer tunnels, or red teams
* Validation: Verify approved product and tenant, support ticket, installer
  source, operator identity, and target population.

### Hypothesis 12: A trusted management console becomes an execution channel

* Hypothesis: Intune, EDR remote response, SCCM, or a patch console is used to
  deploy scripts, alter allowlists, or install tools.
* Telemetry: `CloudAppEvents`, EDR and device-management console audit,
  `DeviceEvents`, `DeviceProcessEvents`, and administrative logs
* Logic: Detect scripts, registry changes, allowlist changes, or deployments
  from a first-seen administrator, location, or console workflow across one or
  more devices within one to six hours.
* Pivots: Administrator, console session, script, target device count, IP
* False positives: Incident response or software rollout
* Validation: Require change approval, second-administrator confirmation,
  script provenance, and review of all targeted devices.

### Hypothesis 13: Identity compromise reaches vSphere

* Hypothesis: A new vSphere administrator or group member accesses vCenter and
  enables persistent remote administration.
* Telemetry: AD events 4728 and 4732, vCenter events, VCSA journald or syslog,
  ESXi logs, PAM, and network flow
* Logic: Correlate administrator-group modification with a new-source vCenter
  login, appliance reboot, SSH enablement, or Teleport files within two hours.
* Pivots: Account, source IP, vCenter, VCSA, ESXi host, group, PAM checkout
* False positives: Planned virtualization maintenance
* Validation: Confirm maintenance window, dedicated privileged identity, PAM
  record, source workstation, and remote-tool authorization.

### Hypothesis 14: Virtual-disk manipulation exposes privileged data

* Hypothesis: An attacker powers off a critical VM and attaches its VMDK to an
  unrelated or orphaned VM to extract credentials or reset access.
* Telemetry: vCenter `VmPoweredOffEvent`, `VmReconfiguredEvent`, ESXi
  `hostd.log`, `vpxa.log`, and datastore audit
* Logic: Find critical VM power-off followed by disk detach or attachment to a
  different VM within 30 to 60 minutes, especially outside a change window.
* Pivots: VM, datastore, VMDK path, actor, destination VM, source IP
* False positives: Recovery, migration, or digital forensics
* Validation: Confirm approved operation, source and destination ownership,
  ticket, data classification, and subsequent account activity.

### Hypothesis 15: Backup sabotage precedes destructive impact

* Hypothesis: The actor gains backup privilege and deletes jobs, repositories,
  snapshots, or immutable copies before encryption.
* Telemetry: AD group events, Windows logons, Veeam or other backup audit,
  vCenter events, storage logs, and PAM
* Logic: Correlate backup-administrator membership or unusual interactive logon
  with mass deletion or configuration changes within one hour.
* Pivots: User, backup server, repository, job, snapshot, source host
* False positives: Retention cleanup or disaster-recovery testing
* Validation: Confirm change approval, retention policy, immutable-copy health,
  secondary credentials, and restoration readiness.

### Hypothesis 16: Native ETL services exfiltrate SaaS data

* Hypothesis: A compromised administrator creates Airbyte, Fivetran, Azure Data
  Factory, backup, or similar connectors to an attacker-controlled destination.
* Telemetry: SaaS audit, connector logs, `AzureActivity`, cloud storage audit,
  S3 or SFTP logs, and CASB
* Logic: Detect a new or changed connector exporting a sensitive dataset to a
  first-seen external destination over 24 hours to seven days.
* Pivots: Creator, connector, dataset, destination, credential, transfer volume
* False positives: Approved analytics, migration, backup, or vendor integration
* Validation: Verify destination ownership, contract, change record, data
  classification, credential owner, and expected volume.

### Hypothesis 17: Mailbox changes conceal security activity

* Hypothesis: The attacker deletes suspicious-activity messages or creates
  rules that hide security notifications and response communications.
* Telemetry: Exchange audit, `OfficeActivity`, `CloudAppEvents`, mailbox rule
  inventory, and identity audit
* Logic: Detect new deletion, forwarding, move, or hiding rules matching
  security senders or terms after suspicious administrative activity within
  four hours.
* Pivots: Mailbox, actor, rule name, condition, sender domain, target folder
* False positives: User inbox cleanup or approved automation
* Validation: Confirm mailbox owner intent, rule creator, session, affected
  messages, and whether alerts were acknowledged elsewhere.

### Hypothesis 18: ESXi behavior signals imminent encryption

* Hypothesis: The actor uses SSH or SCP, shuts down many VMs, changes ESXi
  security controls, or runs an unsigned encryptor.
* Telemetry: ESXi `auth.log`, `shell.log`, audit records, vCenter events,
  network flow, and datastore activity
* Logic: Correlate new-source privileged access with mass VM shutdown,
  `execInstalledOnly` changes, payload transfer, or unsigned execution within
  15 to 60 minutes.
* Pivots: Host, root session, source IP, account, command, binary, datastore
* False positives: Emergency maintenance or approved recovery work
* Validation: Immediately verify the administrator and change window, isolate
  management access where appropriate, preserve remote logs, and check backup
  integrity.

## Defensive Priorities

1. Require phishing-resistant MFA and managed-device context for privileged,
   VPN, IdP, virtualization, backup, and security-console access.
2. Replace knowledge-based help-desk verification with high-assurance callback,
   visual or in-person verification, and dual approval for privileged resets.
3. Correlate Entra, Okta, M365, PAM, EDR-console, Azure, SaaS, vCenter, ESXi,
   backup, help-desk, and telephony audit data.
4. Decouple AD identities from vSphere, backup, PAM, and security control
   planes. Use dedicated privileged accounts and privileged access workstations.
5. Restrict federation, MFA registration, service-principal credentials, cloud
   VM creation, Intune deployment, and EDR response functions.
6. Allowlist approved RMM products and tenant identifiers, not executable names
   or signatures alone.
7. Maintain immutable, identity-isolated backups and test restoration.
8. Send VCSA and ESXi logs to remote storage. Monitor SSH, VMDK reattachment,
   VM power events, group changes, and security-setting changes.
9. Restrict management-plane egress and baseline ETL, backup, file-sharing,
   tunneling, and cloud-storage destinations.
10. Conduct incident response through verified out-of-band channels because the
    actor may monitor or manipulate normal collaboration systems.

## Collection Gaps and Uncertainty

* Endpoint-only visibility cannot detect much of the actor's IdP, SaaS,
  hypervisor, and cloud-control-plane activity.
* SaaS licensing and retention may not preserve sufficiently granular audit
  events for delayed investigations.
* Help-desk calls, ticket actions, telecom changes, MFA events, and sign-ins are
  rarely joined under a common correlation identifier.
* ESXi audit logging is not enabled by default, and local evidence can be lost
  after reboot or encryption.
* Shared RMM, VPN, residential proxy, cloud, and file-hosting indicators have
  substantial false-positive potential.
* Vendor cluster membership and alias relationships can change over time.
* RansomHub affiliation is directly stated by Mandiant. DragonForce is
  supported by government trusted-third-party reporting and campaign evidence.
  A Qilin affiliation was not verified.
* Public victim reporting often combines victim-confirmed impact with
  third-party actor assessment. Preserve these as separate confidence fields.
* No tenant telemetry was queried and no detection or control coverage was
  validated for this report.

## Sources

1. S1, Microsoft Threat Intelligence, [Octo Tempest crosses boundaries to facilitate extortion, encryption, and destruction](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/), published October 25, 2023 and updated November 1, 2023. Supports actor evolution, BlackCat affiliation, hybrid attack flow, tools, exfiltration, and detection opportunities.
2. S2, Mandiant, [Why Are You Texting Me? UNC3944 Leverages SMS Phishing Campaigns for SIM Swapping, Ransomware, Extortion, and Notoriety](https://cloud.google.com/blog/topics/threat-intelligence/unc3944-sms-phishing-sim-swapping-ransomware/), published September 14, 2023. Supports alias overlap, phishing kits, cloud persistence, Azure abuse, and tools.
3. S3, Mandiant, [UNC3944 Targets SaaS Applications](https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications), published June 14, 2024. Supports SaaS targeting, Okta abuse, cloud VMs, PCUnlocker, EDR-console abuse, ETL exfiltration, and data-only extortion.
4. S4, Microsoft Incident Response, [Octo Tempest: Hybrid identity compromise recovery](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/octo-tempest-hybrid-identity-compromise-recovery/4166783), published June 19, 2024. Supports federation, service-principal persistence, Azure and Intune abuse, MFA registrations, and recovery implications.
5. S5, Mandiant, [Defending Against UNC3944: Cybercrime Hardening Guidance from the Frontlines](https://cloud.google.com/blog/topics/threat-intelligence/unc3944-proactive-hardening-recommendations), published May 7, 2025. Supports victimology, sector waves, RansomHub affiliation, DragonForce uncertainty, identity controls, and hunting guidance.
6. S6, Mandiant, [From Help Desk to Hypervisor: Defending Your VMware vSphere Estate from UNC3944](https://cloud.google.com/blog/topics/threat-intelligence/defending-vsphere-from-unc3944), published July 24, 2025. Supports the vSphere lifecycle, Teleport, VMDK theft, backup sabotage, ESXi encryption, and logging requirements.
7. S7, FBI, CISA, RCMP, ASD, AFP, CCCS, and NCSC, [Scattered Spider](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/scattered-spider), originally published November 16, 2023 and substantially updated July 29, 2025. Supports government attribution, TTPs through June 2025, DragonForce, RattyRAT, Snowflake activity, and ATT&CK v17 mappings.
8. S8, Okta Defensive Cyber Operations, [Detecting Scatter Swine: Insights into a Relentless Phishing Campaign](https://sec.okta.com/scatterswine), published August 25, 2022 and updated March 8, 2024. Supports Twilio-related scope, Scatter Swine behavior, infrastructure patterns, and Okta detection guidance.
9. S9, Okta Defensive Cyber Operations, [Cross-Tenant Impersonation: Prevention and Detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection), published September 1, 2023 and updated March 8, 2024. Supports help-desk attacks, Super Admin compromise, Org2Org impersonation, event types, and historical IPs.
10. S10, MITRE ATT&CK, [Scattered Spider, G1015](https://attack.mitre.org/groups/G1015/), created July 5, 2023 and last modified July 31, 2026. Supports associated groups and current Enterprise technique identifiers and names.
11. S11, Trellix, [Scattered Spider: The Modus Operandi](https://www.trellix.com/en-us/about/newsroom/stories/research/scattered-spider-the-modus-operandi.html), published August 17, 2023. Supports early campaigns, POORTRY and STONESTOP, vulnerable-driver activity, and historical IOCs.
12. S12, Check Point Research, [Exposing Scattered Spider: New Indicators Highlight Growing Threat to Enterprises and Aviation](https://blog.checkpoint.com/research/exposing-scattered-spider-new-indicators-highlight-growing-threat-to-enterprises-and-aviation/), published July 7, 2025. Supports candidate phishing-domain patterns and aviation-focused reporting; the source warns that candidates are not all confirmed malicious.
13. S13, BBC News, [Co-op cyber attack affects customer data, firm admits, after hackers contact BBC](https://www.bbc.com/news/articles/crkx3vy54nzo), published May 2, 2025. Supports confirmed Co-op data theft and DragonForce claims while preserving uncertainty over affiliate identity.
14. CrowdStrike, [Scattered Spider adversary profile](https://www.crowdstrike.com/en-us/adversaries/scattered-spider/), retrieved as current in September 2026. Supports community identifiers, financial motivation, and early targeting.

