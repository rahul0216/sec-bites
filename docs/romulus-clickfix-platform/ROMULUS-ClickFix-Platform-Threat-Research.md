---
title: "ROMULUS ClickFix Platform Threat Research"
description: "Threat research of ROMULUS infrastructure, ClickFix delivery, Stardock DLL sideloading, LegionLoader, indicators, and defensive priorities"
ms.date: 2026-10-17
keywords:
  - ROMULUS
  - ClickFix
  - LegionLoader
  - DLL sideloading
  - Custom GPT abuse
estimated_reading_time: 10
---

## Executive summary

ROMULUS is a reusable, multi-payload malware-delivery platform identified by Forescout Vedere Labs in research published on October 15, 2026. Researchers identified six servers exposing a matching ROMULUS authentication frontend and analyzed two delivery routes on `86.109.75[.]7`: a trojanized Stardock DeElevation MSI package and a nested-archive chain delivering LegionLoader. ROMULUS is a delivery backend, not a confirmed malware family or attributed threat actor.

The infrastructure overlaps with a Huntress investigation into attackers abusing ChatGPT Custom GPTs to direct users to fake verification pages. Those pages used ClickFix social engineering to persuade users to execute PowerShell commands. The connection is supported by shared delivery infrastructure and matching Stardock package components; it does not establish that every ROMULUS infection originated from ChatGPT.

The most important defensive opportunities are correlated execution sequences: user-driven PowerShell staging, silent MSI installation and DLL sideloading, or password-protected archive extraction followed by an unusually large executable. In the LegionLoader route, a sub-megabyte archive expands into an 882,716,672-byte executable, approximately 842 MiB, with repetitive padding that could exceed security-tool analysis limits. Actual bypass depends on product behavior and configuration, not file size alone.

Operator identity, service model, victim totals, sector distribution, and geographic targeting remain unresolved. Forescout explicitly found no evidence linking ROMULUS to the separately reported RomulusLoader associated with Silver Fox.

## Identity and attribution assessment

| Question                         | Assessment                                                                                                        | Confidence   |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------ |
| What is ROMULUS?                 | A named delivery panel/backend supporting multiple payload routes.                                                | High         |
| Is it a single malware family?   | No. The analyzed routes delivered different loader chains.                                                        | High         |
| Who operates it?                 | Unknown. No defensible actor or country attribution is available from the reviewed evidence.                      | Unknown      |
| Is it a commercial service?      | Unproven. A private panel, paid service, affiliate framework, or copied software remain possible explanations.    | Unknown      |
| Is the Custom GPT link real?     | Shared infrastructure and matching Stardock components connect it to the Huntress investigation.                  | High         |
| Is ROMULUS RomulusLoader?        | No relationship is established. Similar naming must not be used to import Silver Fox attribution.                 | High         |
| Is ChatGPT itself compromised?   | The evidence describes attacker-created Custom GPT content abusing platform trust, not a compromise of ChatGPT.   | High         |

Confidence reflects the specificity of the published evidence, not independent verification of infrastructure ownership.

## Reporting timeline

| Date         | Source-reported milestone                                                                                                                        |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 2026-09-25   | Huntress says an initial malicious Custom GPT was taken down. Forescout separately reports this creation timestamp inside the analyzed MSI.      |
| 2026-09-27   | Huntress discovered a replacement Custom GPT linked to the campaign.                                                                             |
| 2026-09-28   | Huntress published its Custom GPT, ClickFix, and RAT investigation.                                                                              |
| 2026-10-14   | Huntress updated its report with continuing impact, a new Google Sites path, and `gptverification[.]com`.                                        |
| 2026-10-15   | Forescout published the ROMULUS platform analysis, connecting infrastructure and documenting the Stardock and LegionLoader routes.               |
| 2026-10-17   | This research synthesis was prepared from the sources listed below.                                                                              |

The MSI timestamp is an artifact property, not a trustworthy campaign-start date. Huntress reported at least 40 incidents associated with the specific Google Sites domain and confirmed a Custom GPT origin in two; those figures must not be presented as ROMULUS-wide victim totals.

## Platform architecture and infrastructure

Forescout identified matching ROMULUS login panels using historical VirusTotal and Shodan pivots. The frontend submitted credentials to `/api/login`, retained a returned token, and redirected successful logins to `/`. A matching `/stats.htm` page on `86.109.75[.]7` displayed installation/run counters, a 14-day timeline, history, and country breakdowns. This is evidence of campaign-management functionality, not a verified count of distinct compromised organizations.

The delivery interface separates scripts from installer artifacts:

| Route pattern     | Reported purpose                                                                                                    |
| ----------------- | ------------------------------------------------------------------------------------------------------------------- |
| `/s/<token>`      | Supplies a PowerShell staging script.                                                                               |
| `/app/<token>`    | Supplies installer artifacts, including MSI filenames beneath the route.                                            |
| 12-hex token      | Selects observed delivery routes; whether it represents a campaign, victim, assignment, or job remains unresolved.  |

The same staging mechanism supported both an MSI route and a route that fetched an archive from another domain. Other observed MSI filenames included `FreePhotoSlideShowDesktop_signed.msi`, `235235.msi`, and `overlay.msi`; Forescout did not analyze those packages. Their names do not prove their contents, signatures, or eventual malware family.

## Attack chain

### Entry and shared PowerShell staging

In Huntress's observed campaign, some users searching for ChatGPT encountered sponsored results leading to an attacker-created Custom GPT on the legitimate platform. The GPT presented a service-availability notice and directed users to a supposed backup site. The linked page impersonated a Cloudflare CAPTCHA and instructed the victim to copy and execute a command. This is social engineering through a trusted service, not evidence of prompt injection against a separate victim model or a model jailbreak.

Forescout recovered two heavily obfuscated PowerShell scripts generated from a common template. Both stored their script path in `$env:__ST`, reconstructed code from integer arrays, executed reconstructed text through `[scriptblock]::Create`, and removed themselves before exit. Payload-specific keys, variable names, and logic varied.

```text
Observed Custom GPT campaign
  Sponsored result -> attacker-created Custom GPT -> fake verification page
  -> victim pastes command -> PowerShell staging on linked infrastructure

ROMULUS routes analyzed by Forescout
  /s/<token> -> shared obfuscated PowerShell staging
    Route A -> trojanized Stardock MSI -> DLL sideloading -> loader/RAT chain
    Route B -> encrypted nested 7z archives -> inflated PE -> LegionLoader
```

The entry path above was observed in the linked campaign. The published evidence does not demonstrate the same lure for every Route B victim.

### Route A: trojanized Stardock DeElevation package

The staging script associated with token `19481b28bd67` downloaded `IconEdit2Turb.msi` using decimal IPv4 notation. The numeric host `1450003207` represents `86.109.75[.]7`. It saved a GUID-prefixed installer in `%TEMP%`, invoked `Unblock-File`, and launched `msiexec.exe` with `/i`, `/qn`, and `/norestart`. Removing the download marker is not equivalent to disabling Defender or proving an antivirus bypass.

The x64 MSI identified itself as `Stardock Smart DeElevation Tool` and installed beneath `%LOCALAPPDATA%\Programs\Stardock Smart DeElevation Tool\`. A `WixShellExec` custom action launched legitimate `DeElevate64.exe`. That executable loaded a patched `DeElevator64.dll`, whose added dependency transferred control into malicious `I++u.dll`. Additional packaged components included helper DLLs, `Build.dat`, and `execute_engine_disconnect.raw`.

Huntress found that the Stardock variant retained the same final RAT as its earlier Canon-based chain. Its related analysis describes encrypted payload storage, loader shellcode, and persistence logic. Those linked-campaign findings should not be generalized to every ROMULUS installer. Legitimate Stardock and Canon binaries are abused as hosts; their names or signatures alone are not proof of maliciousness.

### Route B: nested archives and LegionLoader

The staging script associated with token `6c67e0336a7b` hid its PowerShell console using dynamically defined Windows API calls, retrieved `orbitflownetwork[.]lol/dl/J8QkZUVJgV.7z`, and obtained legitimate `7zr.exe` from GitHub. It extracted two password-protected archive layers before launching the carrier executable. The archive utility and GitHub service are not inherently malicious.

The inner archive contained five high-entropy `.bin` files and an 882,716,672-byte x64 PE. Most of the carrier's oversized `.reloc` section consisted of repeating padding; the relocation directory described only 108 bytes of actual relocation data. Forescout reports that the meaningful headers, code, configuration, and cryptographic material remained in an approximately 2 MB prefix. The carrier's large size is deliberate padding, not evidence of comparably large functional code.

The executable decrypted embedded shellcode using AES-256, removed padding, and reversed decrypted bytes. A second decryptor repeated the AES-CBC and byte-reversal sequence, then manually mapped a 475,648-byte LegionLoader PE by allocating memory, resolving imports, applying relocations, and invoking its entry point. The five `.bin` files were not referenced in the final PE traced by Forescout; their role remains unknown. Manual PE mapping alone does not prove injection into another process.

### LegionLoader command and control

The analyzed configuration used `smashshape[.]com`, with `/nfront.php` for registration/task retrieval and `/nback.php` for results. WinHTTP requests declared `application/x-www-form-urlencoded`, but carried a single Base64 string containing an RC4-encrypted serialized object rather than ordinary form fields. A recovered 31-byte key protected C2 messages. Separate downstream payload decryption used runtime and embedded 16-byte keys; these mechanisms must not be conflated.

Forescout also describes a stable machine identifier derived from the system volume serial, command-driven PowerShell execution, download handling, and Chrome Local State key handling. AhnLab independently documents LegionLoader capabilities including additional payload execution and Chrome data theft. These are analysis-derived capabilities, not proof that browser credentials were successfully stolen from every affected endpoint.

## Indicators and investigative artifacts

Indicators below are source-reported, not independently confirmed active. Network observables retain defanged source values; normalized hosts are provided as inert code text for authorized matching. Paths and hashes preserve their original case and bytes. A source-confirmed delivery role is distinct from a panel-only association. Reassess age, ownership, and local context before enforcement.

### Network indicators

| Type     | Source value                 | Normalized host        | Evidence and confidence                                                           |
| -------- | ---------------------------- | ---------------------- | --------------------------------------------------------------------------------- |
| IPv4     | `96.62.224[.]81`             | `96.62.224.81`         | Confirmed in reporting: Huntress delivery node; matching ROMULUS frontend.        |
| IPv4     | `86.109.75[.]7`              | `86.109.75.7`          | Confirmed in reporting: host serving both analyzed ROMULUS routes.                |
| IPv4     | `151.240.151[.]223`          | `151.240.151.223`      | Panel association only; payload delivery on this node not individually analyzed.  |
| IPv4     | `23.94.145[.]224`            | `23.94.145.224`        | Panel association only; payload delivery on this node not individually analyzed.  |
| IPv4     | `93.152.224[.]118`           | `93.152.224.118`       | Panel association only; payload delivery on this node not individually analyzed.  |
| IPv4     | `2.27.248[.]127`             | `2.27.248.127`         | Panel association only; payload delivery on this node not individually analyzed.  |
| Domain   | `orbitflownetwork[.]lol`     | `orbitflownetwork.lol` | Confirmed in reporting: Route B archive delivery.                                 |
| Domain   | `smashshape[.]com`           | `smashshape.com`       | Confirmed in reporting: analyzed LegionLoader C2 configuration.                   |

Forescout's infrastructure bullet list renders some IPs incompletely; the full addresses above come from its explicit IOC table and opening narrative, not reconstructed octets. Decimal host forms are `1614733393` for `96.62.224.81` and `1450003207` for `86.109.75.7`. Search both original command strings and normalized network destinations.

### URL and path pivots

| Defanged observable                                                      | Role and evidence boundary                                                      |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `hxxp://86.109.75[.]7/s/19481b28bd67`                                    | Route A PowerShell stager.                                                      |
| `hxxp://86.109.75[.]7/app/19481b28bd67/IconEdit2Turb.msi`                | Route A MSI package.                                                            |
| `hxxp://86.109.75[.]7/s/6c67e0336a7b`                                    | Route B PowerShell stager.                                                      |
| `orbitflownetwork[.]lol/dl/J8QkZUVJgV.7z`                                | Route B archive path; scheme intentionally not inferred.                        |
| `smashshape[.]com/nfront.php`                                            | LegionLoader registration/tasking path; scheme not inferred.                    |
| `smashshape[.]com/nback.php`                                             | LegionLoader results path; scheme not inferred.                                 |
| `novatrafficcore[.]lol/AsFJfTQYDTkpOg6K`                                 | Earlier observed stager; direct ROMULUS relationship explicitly unconfirmed.    |

Related Huntress campaign leads include `gptverification[.]com` and the specific Google Sites paths `/view/antibot172881` and `/view/antibot381122/`. These are campaign-context pivots, not proof of LegionLoader delivery. Do not block all of Google Sites, GitHub, ChatGPT, or Cloudflare on the basis of their abuse in these chains.

### Selected SHA-256 indicators

All values below were published in Forescout's IOC or component tables. Hash syntax was checked for 64 hexadecimal characters; sample contents and computed hashes were not independently verified.

| Artifact                                     | SHA-256                                                              | Interpretation                                        |
| -------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------- |
| Route A `IconEdit2Turb.msi`                  | `91a22cf3154944897cbcaffc7d20d4596e972d280ee134197d41d8d8eefb0fe2`   | Reported trojanized installer.                        |
| Route A PowerShell stager                    | `6147d56b5e35d6435d83adb49908c40a97520a0c3379121104816e37cbd1df28`   | Reported staging script.                              |
| Route B PowerShell stager                    | `62ca523863337ac5d6b1c4d9ae262d1b2eb7dd9ca764b702ef719c84b2437a39`   | Reported staging script.                              |
| `DeElevate64.exe`                            | `22869e3326fe1de011cd500e666769027126c5c440b76837baf55139f30094e4`   | Legitimate host; contextual lead, not malware alone.  |
| Patched `DeElevator64.dll`                   | `0457414c4504b70115798eee9c8384a8bf9e793461ffb2e0661a6dcc6ed4809f`   | Reported patched sideloaded DLL.                      |
| `I++u.dll`                                   | `3cd1484cc5bf10e22d79784beba58a75d7b126c46efb5e1a85d6aab884447621`   | Reported malicious loader.                            |
| `Build.dat`                                  | `d3fda1e6cf886fd530bf62e2d16c39ad23ed12a2c933fc211f1f4876ceaa033e`   | Reported loader container.                            |
| `execute_engine_disconnect.raw`              | `d5acf44658f0dce90bd160f15d8e07a96938c81661d87dc7e9cb0107863bfb90`   | Reported encrypted payload storage.                   |
| `J8QkZUVJgV.7z`                              | `3b074d6f9bc399fbb1362aeb6ffe1e02013f10e8fa095fc2b3381d8cec270435`   | Reported outer archive.                               |
| `CarJqRHyOtBu3mI.7z`                         | `4e2955f5f5861a51c07fe386d782a3872cfe1c9e750295daa94626f2bd97d84a`   | Reported inner archive.                               |
| Inflated carrier PE                          | `1f403ac059f172e99968ce96bd0ef1bd1981070b454e3e5d75a71368c3c8762a`   | Reported 882,716,672-byte outer executable.           |
| Stage 2 shellcode                            | `4e0941d243c0b16e9019e4f9c5eb0f6e6630af4d44d9677611917450bb2e696e`   | Extracted stage, not necessarily a disk artifact.     |
| Stage 3 LegionLoader PE                      | `2e3d378d6a842af2404dfcd1dcbfc0df84b01b799b2c8270ddbfe5eb18837762`   | Extracted final PE, not necessarily a disk artifact.  |

## MITRE ATT&CK mapping

Enterprise ATT&CK fits the supported endpoint behaviors. The use of an attacker-created Custom GPT is documented as lure delivery; it does not establish model compromise, prompt injection, poisoning, or model theft. No ATLAS technique is assigned without that additional evidence.

The linked MITRE technique pages were checked during this research. Confidence is high for the listed mappings because each is tied to a concrete reported action. Tactics describe the supported role here, not proof that every possible objective associated with a technique was achieved.

| Technique and authoritative reference                                                                    | Tactic in this chain         | Evidence and confidence                                                          |
| -------------------------------------------------------------------------------------------------------- | ---------------------------- | -------------------------------------------------------------------------------- |
| [T1204.004 Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/)                     | Execution                    | High: fake verification prompts induce pasted command execution.            |
| [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)                                   | Execution                    | High: shared staging scripts and LegionLoader command handling.             |
| [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)                                | Command and Control          | High: script, MSI, archive, and utility downloads.                          |
| [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/)                          | Defense Evasion              | High: integer-array reconstruction and layered script obfuscation.          |
| [T1027.001 Binary Padding](https://attack.mitre.org/techniques/T1027/001/)                               | Defense Evasion              | High: repetitive padding inflates the carrier's `.reloc` section.           |
| [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)              | Defense Evasion              | High: archive extraction, AES stage decryption, and byte reversal.          |
| [T1218.007 Msiexec](https://attack.mitre.org/techniques/T1218/007/)                                      | Defense Evasion              | High: Windows Installer executes the trojanized MSI silently.               |
| [T1574.001 DLL](https://attack.mitre.org/techniques/T1574/001/)                                          | Defense Evasion              | High: legitimate host loads the patched DLL and malicious dependency.       |

Forescout used the historical label `T1574.002 DLL Side-Loading`. At research time that MITRE URL redirected to `T1574.001`, whose current page is named `DLL` and explicitly covers sideloading. The table uses the current destination while preserving the source's terminology here. Persistence, lateral movement, exfiltration, ransomware deployment, and process injection are not assigned as platform-wide behaviors without route-specific evidence.

## Detection and hunting priorities

These are implementation requirements for a SOC, not executable or validated hunting queries. Confirm local schema, retention, collection policy, event availability, and expected administrative baselines before authoring detections. Prioritize multi-event correlation over isolated filenames or command switches.

| Priority   | Hypothesis                                                                                                    | Required visibility and triage considerations                                                                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1         | User-driven shell execution shortly after a verification-page visit initiates a download.                     | Correlate web/proxy activity, process creation, command lines, account/device identity, and RunMRU where collected. A pasted command may have Explorer ancestry, not the browser. |
| P1         | PowerShell stages an MSI in a writable location and triggers silent installation.                             | Correlate script logging, file creation, `Unblock-File` evidence, and `msiexec` command lines. Software deployment tools can create similar events.                               |
| P1         | Stardock host executes with a patched or unexpected DLL beside it.                                            | Collect image-load telemetry, paths, signatures, and hashes. Compare with known-good software inventory; do not flag all legitimate Stardock installations.                       |
| P1         | PowerShell obtains `7zr.exe`, performs passworded extraction, and launches a new executable.                  | Correlate process and file events, archive extraction arguments, destination directory, and subsequent execution. Legitimate packaging automation is a confounder.                |
| P1         | Oversized executables in user-writable paths receive incomplete analysis.                                     | Review scanner/sandbox skip reasons, file-size policy, PE section metadata, and extraction limits. Test with harmless fixtures rather than the live carrier.                      |
| P2         | Script content matches the shared staging structure rather than changing variable names.                      | PowerShell event 4104 where enabled can expose integer arrays, `$env:__ST`, and `[scriptblock]::Create`. Missing logs do not demonstrate absence of execution.                    |
| P2         | Command strings contain decimal IPv4 destinations while network events use dotted notation.                   | Normalize numeric URL hosts in analysis and correlate with destination IPs. Preserve original strings; generic numeric-host matches require corroboration.                        |
| P2         | LegionLoader sends anomalous form-urlencoded POST bodies to known tasking/results paths.                      | HTTP body visibility or approved TLS inspection is required for framing inspection. DNS or basic connection logs cannot prove this message structure.                             |
| P2         | A non-browser process accesses Chrome Local State following the delivery chain.                               | File-read telemetry or a targeted audit policy is needed. Standard file-creation events do not establish reads; correlate with process lineage and user context.                  |

Useful enrichment includes script deletion events, installer parentage, execution from `%TEMP%`, newly written application directories, and the interval between archive extraction and PE execution. Do not assume a direct PowerShell-to-payload parent relationship: MSI custom actions and Windows Installer service execution can alter process ancestry.

## Prevention and incident response

### Prevent and prepare

1. Train users that CAPTCHA checks, service availability notices, and AI assistants should never require pasting commands into PowerShell, Terminal, or the Windows Run dialog.
2. Apply organization-tested application control to scripts, MSI packages, and executables from user-writable locations. A trusted signature alone must not authorize every neighboring DLL.
3. Enable appropriate PowerShell logging and endpoint process/image-load collection, with access controls and retention that account for potentially sensitive command content.
4. Review controls for encrypted archives, excessive expansion, oversized executables, and skipped scans. Validate actual product behavior using benign fixtures and documented limits.
5. Use scoped URL/domain controls and destination monitoring for confirmed malicious infrastructure, subject to current reputation checks and business-impact review.
6. Establish a reporting path for suspicious Custom GPTs, advertisements, and hosted verification pages. Report specific abusive objects rather than treating shared services as uniformly hostile.

### Respond to suspected execution

1. Isolate the affected endpoint under the organization's incident-response procedure and preserve process trees, script logs, installer events, browser history, and available network telemetry.
2. Determine whether the pasted command ran and whether either payload route executed. A blocked download or quarantined MSI does not by itself prove that earlier execution or persistence did not occur.
3. Collect related installers, DLLs, encrypted storage, archive metadata, and hashes through approved forensic tooling. Do not run recovered scripts or browse live delivery URLs.
4. Examine route-specific persistence. Huntress's Canon variant used both a Run value and a scheduled task named `Canon Configuration Reader`, and running malware could recreate them. That exact name is not a universal ROMULUS marker.
5. Contain or terminate the active implant through approved response tooling before removing its persistence, then verify that removed artifacts do not reappear.
6. Assess browser and account exposure. If credential or session compromise is suspected, revoke relevant sessions and rotate affected credentials from a trusted device; scope the action to the evidence.
7. Hunt across the fleet using both network indicators and correlated behaviors. Verify containment and recovery rather than relying on a single hash removal or clean scan.


## Sources

|      | Source and publication context                                                                                                                                                                                         | Principal contribution                                                                                       |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1   | [Forescout Vedere Labs: ROMULUS, Analysis of a New Multi-Payload ClickFix Delivery Platform](https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/), published 2026-10-15 | Platform identity, six panel hosts, both analyzed routes, configuration, IOCs, and attribution limitations.  |
| 2   | [Huntress: Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix](https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat), published 2026-09-28; visible update 2026-10-14                           | Observed lure, incident context, Canon/Stardock relationship, RAT chain, and persistence cautions.           |
| 3   | [AhnLab ASEC: LegionLoader investigation](https://asec.ahnlab.com/en/95374/), accessed 2026-10-17                                                                                                                      | Independent family-level context for ClickFix delivery, payload handling, and Chrome data-theft capability.  |
