---
title: "Nightmare Eclipse: The Researcher, the Defender Exploits, and the Attacks That Followed"
description: "How Abdelhamid Naceri's Nightmare Eclipse disclosures became part of a wider story about Windows security flaws, public exploits, and real-world attacks"
ms.date: 2026-10-19
ms.topic: concept
keywords:
  - Nightmare-Eclipse
  - Abdelhamid Naceri
  - Chaotic Eclipse
  - BlueHammer
  - RedSun
  - UnDefend
  - RoguePlanet
  - Microsoft Defender
estimated_reading_time: 7
---

## A name behind the exploits

When Nightmare Eclipse publicly identified himself as Abdelhamid Naceri,
he put a name behind a series of Windows exploit releases that had already
drawn attention for reasons beyond their technical details. According to
Cybernews, Naceri is a former Microsoft security researcher based in Germany
who has also used the handles Chaotic Eclipse, MS Nightmare, and Infinite
Nightmare.

By then, some of the exploits associated with his disclosures had appeared
in real attacks. BlueHammer, RedSun, and UnDefend were no longer just code
published for others to inspect. Huntress had reported their use, and CISA
had added the corresponding vulnerabilities to its Known Exploited
Vulnerabilities catalog.

The identity reveal connected those releases to a researcher and a public
dispute with his former employer. It did not connect him to the attackers
using the exploits. Those are two different parts of the story, and keeping
them separate makes what happened easier to understand.

## From an employment dispute to public disclosure

Cybernews describes Naceri's disclosures against the backdrop of his dispute
with Microsoft. The publication reports that he shared a termination letter
giving notice in March 2025 and an employment end date that June. The letter,
as described in the article, did not state a reason for his dismissal.

Naceri has made his own claims about the dispute and its consequences.
Those provide his account of events, not an independently established
explanation for Microsoft's decisions. What is relevant to the technical
story is that the disclosures continued in public, under several handles,
and concerned software with unusually privileged access to Windows systems.

Defender needs that access to do its job. It examines files and acts on
threats in places where an ordinary application has limited authority.
When its own handling of access or file operations is vulnerable, an
attacker may be able to turn an existing foothold into greater control.

That is the connection between the personal story and the security story.
The circumstances of a disclosure may explain why it attracts attention.
The capability it exposes determines why someone else might use it.

## April: the exploits reach live attacks

BlueHammer provides the clearest starting point. Associated with
CVE-2026-33825, it exploited an access-control weakness in Microsoft
Defender to elevate privileges locally. An attacker needed access to the
machine first; this was not a standalone way to break into a Windows
computer remotely.

Huntress reportedly observed exploitation beginning on April 10, 2026.
Microsoft addressed the vulnerability in the April 14 Patch Tuesday
updates. CISA added it to the KEV catalog on April 22.

Those dates capture the problem with treating a public exploit as an
abstract research artifact. In this case, reported malicious use preceded
the fix. The vulnerability was already useful to someone operating on a
compromised machine.

RedSun and UnDefend added two different capabilities to the picture.
Huntress reportedly observed both on April 16.

RedSun, associated with CVE-2026-41091, offered another route to SYSTEM
privileges. Its underlying weakness was improper link resolution before
file access. A privileged component's file operations became a way for a
less-privileged attacker to gain greater authority.

UnDefend, associated with CVE-2026-45498, had a different purpose. It was
reported to interfere with Defender definition updates through a
denial-of-service vulnerability. Rather than giving the attacker a more
privileged account, it could leave the security product's definitions
out of date.

That difference matters. Describing all three as privilege-escalation
exploits misses what UnDefend did. Describing UnDefend as switching off
Defender entirely goes further than the reported behavior supports.

By May 20, CISA had added the RedSun and UnDefend CVEs to KEV as well.
May reporting documented fixes for both. The researcher's confirmation
linked the public exploit names to the CVE identifiers, while CISA's
entries independently supported the finding that the vulnerabilities
were being exploited.

The incident observations also gave some context to that use. Huntress-based
reporting described enumeration commands before exploit invocations,
consistent with an operator examining a machine before attempting the
next step. The picture was of post-compromise activity, not an exploit
demonstration running in isolation.

## Summer: RoguePlanet continues the disclosure story

The releases did not end with the April exploits. RoguePlanet brought
another local privilege-escalation issue into view, this time in
Microsoft's Malware Protection Engine.

Microsoft's record for CVE-2026-50656 explicitly names RoguePlanet and
classifies the weakness as improper link resolution. Reporting described
a race-condition exploit capable of producing a SYSTEM shell, including
on machines with the June 2026 Windows updates installed.

July reporting identified the fixed engine version as 1.1.26060.3008.
That detail also explains why a Windows update date alone does not settle
the question of exposure: the Malware Protection Engine is a separately
versioned component.

RoguePlanet belongs in the same disclosure history, but not in the same
evidence category as the first three exploits. A working public exploit
was reported. Malicious use in the wild was not established in the
material reviewed for this article.

Nor were these four releases the whole of Naceri's work under the
Nightmare Eclipse name. Cybernews describes a broader disclosure history
and discusses later releases, including ShieldBreak and ShieldCrash.
BlueHammer, RedSun, UnDefend, and RoguePlanet are the focus here because
their CVE records let us follow the progression from disclosed capability
to documented fixes, with confirmed exploitation for the first three.

## What changed when the identity became public?

Naceri's self-identification gave the disclosures a clearer personal
history. It did not change the technical effects of the vulnerabilities,
or answer who used them in the incidents Huntress described.

The available accounts do not establish that Naceri ran those intrusions.
They also do not establish a single campaign linking all four exploits,
a common victim sector, or a shared objective. Publishing a tool and
using it against someone else's systems are separate actions.

The patch history needs the same care. BlueHammer had an April fix;
RedSun and UnDefend had fixes documented in May; RoguePlanet's engine
fix was reported in July. All four had documented fixes before this
article's October 19 publication date. Earlier headlines calling them
unpatched zero-days describe an earlier stage of the story.

What remains is more substantial than a dispute played out through
exploit releases. Vulnerabilities in a security product became practical
options for attackers who already had access to Windows machines. Some
could help them gain control; another could interfere with protection
updates. Three have government-corroborated exploitation histories.

The identity reveal tells us who publicly stood behind the disclosures.
The incident evidence tells us why those disclosures mattered beyond
the researcher who published them.

## CVE details

Microsoft's CVE records were checked on October 19, 2026. The severity
ratings and scores below are Microsoft's CVSS version 3.1 base assessments.
The exploit names are mapped through the reporting listed at the end;
Microsoft explicitly names RoguePlanet in its CVE record.

| CVE            | Exploit     | Severity | CVSS 3.1 | Weakness                                         | Exploitation status                          |
|----------------|-------------|----------|----------|--------------------------------------------------|----------------------------------------------|
| CVE-2026-33825 | BlueHammer  | High     | 7.8      | CWE-1220: Insufficient access-control granularity  | CISA KEV addition: April 22, 2026              |
| CVE-2026-41091 | RedSun      | High     | 7.8      | CWE-59: Improper link resolution                  | CISA KEV addition: May 20, 2026                |
| CVE-2026-45498 | UnDefend    | Medium   | 4.0      | CWE-400: Uncontrolled resource consumption        | CISA KEV addition: May 20, 2026                |
| CVE-2026-50656 | RoguePlanet | High     | 7.8      | CWE-59: Improper link resolution                  | Public exploit; malicious use not established |

### Affected components and fixed versions

Each affected range includes the starting version and excludes the fixed
version. Engine and platform versions refer to different components.
The publication dates below are CVE-record dates, not exploit-release
dates or confirmation that a particular device received a fix.

| CVE            | Component                    | Affected range                              | Fixed version    | CVE published  |
|----------------|------------------------------|---------------------------------------------|------------------|----------------|
| CVE-2026-33825 | Defender Antimalware Platform | 4.0.0.0 <= version < 4.18.26030.3011          | 4.18.26030.3011  | April 14, 2026 |
| CVE-2026-41091 | Malware Protection Engine    | 1.1.0.0 <= version < 1.1.26040.8             | 1.1.26040.8      | May 20, 2026   |
| CVE-2026-45498 | Defender Antimalware Platform | 4.0.0.0 <= version < 4.18.26040.7            | 4.18.26040.7     | May 20, 2026   |
| CVE-2026-50656 | Malware Protection Engine    | 1.1.0.0 <= version < 1.1.26060.3008          | 1.1.26060.3008   | June 16, 2026  |

### Scoring context

BlueHammer, RedSun, and RoguePlanet share the base vector
`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`: local access, low
attack complexity, low privileges required, and no user interaction, with
high potential confidentiality, integrity, and availability impacts.

UnDefend's base vector is
`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`: local access, low
complexity, no privileges or user interaction required, and a low
availability impact without direct confidentiality or integrity impact.

These base vectors omit the temporal metrics in the source records.
They describe the vulnerabilities' scoring characteristics, not an
observed sequence of actions in every incident.

## References

### Identity and disclosure history

* [Cybernews: Windows exploit researcher Nightmare Eclipse reveals identity](https://cybernews.com/security/nightmare-eclipse-abdelhamid-naceri-microsoft-researcher/).
  Accessed October 19, 2026. Reports Naceri's self-identification,
  former Microsoft role, additional handles, and broader disclosure
  history. Employment-dispute allegations remain attributed claims.

### Exploitation and patch reporting

* [The Hacker News: Three Microsoft Defender Zero-Days Actively Exploited; Two Still Unpatched](https://thehackernews.com/2026/04/three-microsoft-defender-zero-days.html).
  April 17, 2026. Includes Huntress-reported exploitation observations.
  The headline reflects the patch status at that time.
* [The Hacker News: Microsoft Warns of Two Actively Exploited Defender Vulnerabilities](https://thehackernews.com/2026/05/microsoft-warns-of-two-actively.html).
  May 21, 2026. Covers RedSun and UnDefend, fixes, and the researcher's
  confirmation of their CVE associations.
* [The Hacker News: Microsoft Patches RoguePlanet Defender Flaw That Can Grant SYSTEM Privileges](https://thehackernews.com/2026/07/microsoft-patches-rogueplanet-defender.html).
  July 9, 2026. Covers RoguePlanet's reported capability and engine fix.
* [CISA: Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/22/cisa-adds-one-known-exploited-vulnerability-catalog).
  April 22, 2026. Covers CVE-2026-33825.
* [CISA: Adds Seven Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/05/20/cisa-adds-seven-known-exploited-vulnerabilities-catalog).
  May 20, 2026. Includes CVE-2026-41091 and CVE-2026-45498.

### Microsoft-authored CVE records

* [CVE-2026-33825: Microsoft Defender elevation of privilege](https://cveawg.mitre.org/api/cve/CVE-2026-33825).
  Published April 14, 2026; updated October 15, 2026.
* [CVE-2026-41091: Microsoft Defender elevation of privilege](https://cveawg.mitre.org/api/cve/CVE-2026-41091).
  Published May 20, 2026; updated August 10, 2026.
* [CVE-2026-45498: Microsoft Defender denial of service](https://cveawg.mitre.org/api/cve/CVE-2026-45498).
  Published May 20, 2026; updated August 10, 2026.
* [CVE-2026-50656: Microsoft Defender elevation of privilege, RoguePlanet](https://cveawg.mitre.org/api/cve/CVE-2026-50656).
  Published June 16, 2026; updated September 24, 2026.
