---
title: "ARTEX AI Pentesting Tool Threat Research"
description: "Technical assessment of ARTEX architecture, observed threat actor use, cloud and identity attack paths, forensic artifacts, and defensive priorities."
ms.date: 2026-11-24
ms.topic: reference
keywords:
  - ARTEX
  - agentic AI
  - Storm-0940
  - Storm-3358
  - cloud security
  - workload identities
  - threat hunting
estimated_reading_time: 20
---

## Executive assessment

ARTEX is an LLM-driven penetration-testing framework that threat actors have
adapted for intrusion operations. It combines a Go backend, an embedded Next.js
console, a PostgreSQL state store, and agents that plan tasks and execute
ordinary security tools. Its significance is not a new exploit or an
undetectable implant. It reduces the operator effort needed to connect
reconnaissance, credential abuse, exploitation, persistence, and collection.

By November 2026, public reporting placed ARTEX in espionage, financial-sector
intrusions, and data-theft operations. Microsoft documented its use by
China-state aligned Storm-0940 and Cambodia-based, financially motivated
Storm-3358. Google Threat Intelligence Group and Mandiant described additional
intrusions involving several actors, including extortion operators. ARTEX
activity should therefore be treated as a tooling assessment, not an actor
attribution.

The most consequential attack paths involve valid credentials and excessive
trust. A leaked application secret, a compromised vendor integration, or an
overprivileged cloud identity can give an agent enough access to enumerate
resources, obtain more credentials, and reach sensitive data. Microsoft
reported one agentic intrusion progressing from public GitHub secret discovery
to Azure Key Vault data exfiltration in five minutes. That observation concerns
the reported agentic credential-abuse activity; it is not a measured runtime
guarantee for ARTEX.

Speed does not mean consistent success. Reported operations included failed
password sprays, malformed API requests, unsuccessful privilege-escalation
attempts, and repeated webshell compilation errors. Those failures leave
evidence. The problem for defenders is whether a successful branch completes
before the surrounding noise receives attention.


## What ARTEX is, and what it is not

ARTEX turns a natural-language objective into a sequence of tool-driven tasks.
An operator defines a target and goal; the framework explores available attack
paths, records findings, and uses those findings to decide what to attempt next.
Human operators can monitor and steer the process.

That makes ARTEX different from a static checklist scanner, but not independent
of conventional intrusion requirements. It still needs reachable targets,
usable tools, a compatible model, and a weakness or sufficient authorization
to cross each security boundary.

ARTEX is not:

* A single malware family with one stable executable hash
* A vulnerability with a universal patch or CVE
* A synonym for every AI-assisted intrusion
* Evidence that an attacker has bypassed MFA or discovered a zero-day
* A reliable attribution marker for one country, group, or motive

The framework may run on infrastructure outside the victim's estate. In that
case, the victim sees HTTP requests, authentication events, cloud operations,
and any target-side execution, not necessarily an `artex` process.

Conversely, an ARTEX installation on an internal machine may be an authorized
assessment platform. The installation becomes security-relevant when its owner,
scope, actions, or access cannot be accounted for.

## Provenance and public timeline

The original project was published under the GitHub identity Autumn-27.
Wiz dates its publication to July 2026. Reporting describes the original
repository becoming unavailable in October following misuse. Independent
forks preserved access to the code, including the multilingual Global Edition.
The withdrawal of the original repository did not withdraw those copies.

| Period or date         | Publicly reported development                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| July 2026              | Wiz dates the original ARTEX publication to this month.                                                           |
| Late August 2026       | GTIG and Mandiant place observed abuse of ARTEX and other agentic frameworks in this period.                      |
| September 2026         | Microsoft dates Storm-0940 ARTEX targeting to at least September.                                                 |
| October 8, 2026        | Wiz reports that the original developer made the project closed-source.                                           |
| October 10-14, 2026    | Microsoft observes the large Storm-0940 cross-tenant password-spray campaign.                                     |
| October 15-16, 2026    | Downstream application abuse and ConnectWise disclosures become central to the reported investigation.            |
| October 21, 2026       | Microsoft publishes its Storm-0940 and ConnectWise supply-chain assessment.                                       |
| October 31, 2026       | GTIG and Mandiant publish incident observations involving ARTEX and other frameworks.                             |
| November 5, 2026       | Microsoft reports agentic exposed-secret abuse; CERT-EU publishes an ARTEX warning.                               |
| November 6, 2026       | Microsoft reports Storm-3358 use against financial organizations.                                                 |
| November 13, 2026      | The FBI publishes an ARTEX threat overview and accompanying indicator CSV.                                        |

These are publication dates and reported observation windows, not a complete
history of the tool. They do not establish its first malicious use.

## Architecture and operating model

### Planning and execution

The public Global Edition describes four principal agent roles:

* A goals component decomposes objectives and extracts scope.
* A planner chooses new directions and creates work intents.
* Workers claim individual intents and execute real tools.
* A main agent provides the human interaction and steering point.

Google describes six specialized sub-agents in its ARTEX overview. That count
is not identical to the Global Edition's four principal role categories.
Different versions and different ways of grouping components may account for
the difference; the available evidence does not justify imposing one universal
agent count.

The important behavior is the feedback loop:

```text
Operator objective and available access
                  |
                  v
          Planner selects work
                  |
                  v
     Workers execute tools and requests
                  |
                  v
     Results, errors, assets, and findings
                  |
                  v
       Shared state informs next action
                  |
                  +------> Planner selects further work
```

The framework can use external model APIs and compatible alternative
endpoints. Model-provider choice is an operator or deployment decision, not a
fixed indicator of ARTEX.

### Shared state

The Global Edition documents two linked graphs stored in PostgreSQL.
An asset graph tracks the target environment. A separate exploration graph
tracks objectives, work, evidence, and findings. Anchors link investigative
progress to the assets involved.

Workers can search other workers' execution traces. The planner also keeps a
persistent task list so dependent actions can run in order rather than all
being launched at once.

This matters operationally. A route discovered in a source map can become the
next probe. A recovered credential can become input to a cloud permission
check. An API error can cause a revised request rather than end the task.

It also matters for forensics. If responders lawfully acquire the operator
platform or an internal relay running it, the database and recorded worker
traces may explain relationships that target-side logs show only in fragments.

### Tools and traffic

Public reporting identifies Nmap, curl, wget, Python HTTP clients, Norma SDK
WebFetch, and headless Chromium through Playwright among the tools ARTEX can
drive. Wiz also describes workers using Impacket.

The Global Edition documents a traffic-recording proxy and approval controls.
These are platform features, not guarantees that all traffic is recorded or
that a malicious deployment retains the same restrictions. CERT-EU cautions
that scope and destructive-action restrictions rely on configurable controls
and model behavior rather than hard technical enforcement.

The framework does not need to stamp its name on each request. Most
tool-generated traffic can look like the underlying utility or SDK.

## Observed threat activity

### Storm-0940 and downstream application trust

Microsoft attributes the reported ConnectWise multi-tenant application
compromise to Storm-0940, a China-state aligned actor active since 2021.
Its assessment describes ARTEX accelerating reconnaissance, password spraying,
and OAuth application abuse.

Between October 10 and 14, Microsoft observed a spray targeting 327 accounts
across eight organizations from `144.172.64.99`. The recorded volume exceeded
151,000 failed sign-ins, with a peak of approximately 2,900 failures per minute.
Crucially, Microsoft reported no successful authentication, token issuance,
Graph call, or directory change from that spray.

The downstream application activity is a separate finding. After acquiring
application credentials, the actor attempted sign-ins to more than 2,250
tenants using existing application trust. In some environments, follow-on
Microsoft Graph operations included reconnaissance, application credential
changes, and changes involving identities, groups, or privileged roles.

This was not described as an interactive user being persuaded through MFA.
Application-only access used the authority already granted to the compromised
applications. User sign-in controls alone cannot be assumed to cover that path.

Microsoft reported several ARTEX-driven attacks reaching privileged cloud
access in less than three hours. It also explicitly cautioned that the presence
of an affected application, or even a successful authentication, does not by
itself establish data access or exfiltration.

The defensive concern is residual access. An attacker-added credential on
another identity can survive remediation of the original vendor connection.
Closing the entry point is not the same as removing every foothold it enabled.

### Wider targeting of software and IT vendors

Wiz observed a repeatable pattern across environments associated with the
Storm-0940 reporting:

1. Retrieve JavaScript bundles, source maps, runtime configuration, and API
   documentation.
2. Use discovered route names to probe application functionality.
3. Test sign-in, SSO, account recovery, and registration paths.
4. Probe tenant boundaries and object-level authorization.
5. Change endpoints, source infrastructure, or request characteristics when
   blocked.

Some sessions continued for 24 to 30 hours. Wiz described bursts of
authentication attempts with a median spacing of one second and other rapid
SSO variations. Those timings are observations from investigated sessions, not
a fixed ARTEX beacon interval.

Many attempts failed. The relevant progression is that later requests used
information obtained from earlier responses. That relationship is more useful
than treating request volume alone as evidence of AI involvement.

### Exposed secrets and cloud access

Microsoft's November 5 report describes agentic tooling searching public
GitHub repositories for application credentials, cloud secrets, and AI-service
keys, followed by authentication and resource access.

The reported follow-on activity included:

* Successful service-principal authentication across multiple applications and
  tenants
* Enumeration of subscriptions, permissions, resource groups, and model
  deployments
* Requests for storage keys, application settings, connection strings, and
  other credential-bearing configuration
* Access to Key Vault, storage, SharePoint, OneDrive, and mailbox content
* Azure VM Run Command use
* Searches for further secrets in Azure DevOps

Some request sequences showed adaptive correction. Failed ARM requests were
followed within tens of seconds by requests using a different API version and
then successful responses.

Two distinctions matter. A successful response for secret metadata does not
prove retrieval of a secret value. A request to an AI service does not, without
additional evidence, prove successful resource hijacking or that the
compromised service powered the intrusion.

The report discusses ARTEX and related agentic tooling. Its individual
observations should not all be relabeled as independently confirmed ARTEX
executions.

### Storm-3358 and financial-sector intrusions

Microsoft describes Storm-3358 as a Cambodia-based, financially motivated
cluster primarily targeting Southeast Asian financial organizations, with
some larger financial targets elsewhere.

Beginning in October, the cluster combined ARTEX with conventional automation
to scan internet-facing systems and exploit weaknesses including anonymous
file upload and server-side request forgery. Microsoft observed ARTEX agents
using curl and netcat to retrieve additional tooling. WISP, vshell, and
AdaptixC2 were used for persistence and lateral movement.

ARTEX and the follow-on remote-access tooling serve different purposes.
Removing a public application weakness does not remove a RAT already
installed through it. Equally, a WISP or AdaptixC2 finding alone does not prove
that ARTEX delivered it.

### GTIG and Mandiant incident findings

Google and Mandiant documented ARTEX activity involving cloud permission
testing, application and database abuse, Active Directory reconnaissance,
credential access, attempted lateral movement, and data collection.

Several observations are particularly useful to defenders:

* Individual execution bursts lasted roughly 2 to 25 seconds, despite longer
  pauses elsewhere in the operation.
* One AWS permission-probing sequence produced 27 events in 23 seconds of
  active burst time.
* An application and database execution attempt generated approximately 240
  log events, including errors and indications of conflicting worker activity.
* Repeated attempts to write JSP webshells through MySQL logging eventually
  produced working command output after earlier failures.
* An internal Windows database server exchanged scripts and results through
  491 rotating `webhook.site` URLs.
* Reported domain activity included Kerberoasting and subsequent DCSync.

Not every attempted action succeeded. Some cloud privilege-escalation
attempts failed because of invalid instance-profile references. Reported
lateral movement also encountered token restrictions and endpoint protection
before defenders severed access.

GTIG tracks one campaign cluster as UNC7228 and describes overlap with
Microsoft's Storm-0940 reporting. That is a scoped overlap assessment, not a
basis for merging every ARTEX investigation into the same actor.

## Attack paths that deserve priority

These paths summarize reported patterns across separate investigations.
They are not one reconstructed incident.

### Public secret to sensitive cloud data

```text
Publicly exposed credential
  -> application authentication
  -> permission and resource discovery
  -> access to credential stores or sensitive services
  -> collection and possible secondary access
```

The decisive control is the authority behind the credential. Removing it from
a repository does not invalidate copies or tokens already obtained. Rotation,
historical-use review, and investigation of dependent secrets are necessary.

### Vendor identity to downstream tenant persistence

```text
Compromised vendor application credential
  -> existing customer application trust
  -> app-only access
  -> directory and Graph reconnaissance
  -> credential or permission changes where authorized
```

An application ID can be common across tenants while the local
service-principal object ID differs. Investigations need both. Display names
are not reliable identifiers.

### Web application compromise to internal access

```text
Application mapping
  -> exploitable application or authorization weakness
  -> server-side execution or data access
  -> webshell or remote-access tooling
  -> internal discovery and further compromise
```

Anonymous file upload and SSRF do not inherently produce the same outcome.
Successful execution depends on the upload handling, reachable services,
identity context, and other target-specific conditions.

### Existing foothold to domain credential theft

```text
Supplied or recovered credentials
  -> domain and service discovery
  -> service-ticket collection and cracking where feasible
  -> privileged access
  -> directory replication abuse
```

DCSync requires appropriate privileges. ARTEX does not make an unprivileged
account a domain replication principal merely by automating the request.

## Why automation changes the defensive workload

### Useful transitions happen faster

The most important interval is not total session length. It is the interval
between acquiring useful access and exercising it. A campaign may last a day,
yet use a newly discovered secret within minutes.

Defenders should measure time from identity compromise to containment, and
from suspicious privilege change to remediation. Alert creation time is only
one part of that sequence.

### Errors can be part of a successful intrusion

A series of rejected requests may precede the working API version, valid path,
or usable payload. Triage that dismisses a sequence because most responses
failed can overlook the one response that changed access.

The useful question is whether the failures were followed by a meaningful
state change: successful authentication, new credentials, process execution,
or data retrieval.

### Parallel work complicates attribution

Different workers and tools can produce different user agents and overlapping
request sequences. Proxy rotation further weakens source IP as a session key.
Correlate identity, application, target resource, timing, and request
relationships rather than requiring every event to share one address.

None of these characteristics is exclusive to AI. A scripted assessment or a
human-operated framework can produce similar traces. Without stronger
artifacts, describe the finding as automated or adaptive intrusion activity
rather than claiming confirmed ARTEX use.

## Indicators and forensic artifacts

### Campaign-associated network indicators

The addresses below were explicitly published in the reviewed reporting.
"Confirmed in source" means the publication lists the value in that role.
It does not mean the address remains malicious or active on November 24.
Defanged values are retained alongside normalized values for review.

| Published value         | Normalized value   | Published context                                          | Source and observation context                           |
| ----------------------- | ------------------ | ---------------------------------------------------------- | -------------------------------------------------------- |
| `144.172.64[.]60`       | `144.172.64.60`    | Sign-ins and Graph activity using compromised applications | Microsoft, October 21; also present in FBI CSV           |
| `144.172.64[.]99`       | `144.172.64.99`    | Password spray; application sign-ins and Graph activity    | Microsoft, October 10-16 activity; FBI CSV               |
| `144.172.64[.]128`      | `144.172.64.128`   | Sign-ins and Graph activity using compromised applications | Microsoft, October 21; also present in FBI CSV           |
| `199.19.77[.]84`        | `199.19.77.84`     | Agentic application-credential abuse activity              | Microsoft, observed from at least October 28             |
| `199.19.77[.]18`        | `199.19.77.18`     | Credential-abuse sign-ins; identified as a Tor exit node   | Microsoft, November 5; shared infrastructure caveat      |
| `65.87.223[.]26`        | `65.87.223.26`     | Potentially related exploitation and token-access attempts | Microsoft, November 5; campaign association tentative    |
| `157.22.126[.]128`      | `157.22.126.128`   | Separately observed reconnaissance against AI workloads    | Microsoft, November 5; not equivalent to confirmed theft |
| `199.19.95[.]66`        | `199.19.95.66`     | WISP C2 node                                               | Microsoft, first seen November 2; FBI CSV                |
| `199.19.95[.]67`        | `199.19.95.67`     | WISP C2 node                                               | Microsoft, first seen November 2; FBI CSV                |
| `199.19.95[.]68`        | `199.19.95.68`     | WISP C2 node                                               | Microsoft, first seen November 2; FBI CSV                |
| `91.92.240[.]238`       | `91.92.240.238`    | ARTEX server                                               | Microsoft, first seen November 4; FBI CSV                |
| `85.11.168[.]45`        | `85.11.168.45`     | ARTEX server                                               | Microsoft, first seen November 4; FBI CSV                |
| `85.11.167[.]52`        | `85.11.167.52`     | C2 server                                                  | Microsoft, first seen November 4; FBI CSV                |
| `178.16.54[.]129`       | `178.16.54.129`    | ARTEX server                                               | Microsoft IOC table, first seen October 19; FBI CSV      |
| `31.77.229[.]35`        | `31.77.229.35`     | ARTEX server                                               | Microsoft, first seen October 28; FBI CSV                |

The Storm-3358 publication described its listed infrastructure as active as of
November 6. That status has not been independently refreshed here.

There is a material source discrepancy: the November 6 Microsoft sample
Sentinel query contains `178.15.54.129`, while the same article's IOC table
contains `178.16.54.129`. The FBI CSV also contains `178.16.54.129`.
The table value is retained above. The query variant is not promoted to a
confirmed indicator.

The FBI CSV includes additional addresses and `xcai.pro`. Its CSV alone does
not explain the domain's role or assign every entry to a particular actor.
Those entries should be enriched against the full advisory before being
treated as actor-specific infrastructure.

### Application exposure pivots

Microsoft's published hunting examples identify these application IDs:

| Application ID                           | Published application name   |
| ---------------------------------------- | ---------------------------- |
| `506e08f9-6e9a-4da4-942b-a099a03644ae`   | ConnectWise Cloud Backup     |
| `24205314-2b89-4e07-a2a4-579e898a5640`   | ConnectWise - MS Teams       |
| `0de14c77-b9b0-4137-9360-34878a929827`   | ConnectWise - MS Graph       |

These are legitimate application identifiers used as exposure pivots, not
inherently malicious applications. Their presence does not establish abuse.
The October article's prose asks readers to inventory four application IDs,
but the reviewed hunting examples enumerate three. No fourth identifier is
inferred here. Use the vendor's current guidance to resolve the complete
affected-application inventory.

### Target-side and operator-side artifacts

The following strings and artifacts are investigation leads, not universal
ARTEX signatures. Some are documented by the Global Edition rather than
observed in every reported intrusion.

| Artifact or characteristic                          | Where it may be visible         | Interpretation and limitation                                                     |
| --------------------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------- |
| `artex-enrich/1.0`                                  | HTTP access or inspected logs   | Documented enrichment fingerprint; editable and forgeable                         |
| `norma/0.4`                                         | HTTP access or inspected logs   | Norma SDK fingerprint; not unique to ARTEX                                        |
| `artex-selfupdate`                                  | Operator-host egress logs       | Documented updater fingerprint, not a victim-side requirement                     |
| `artex-probe-*`                                     | Files or application records    | Google-observed naming pattern; not a fixed sequence or complete signature        |
| `cl1217.jsp`, `f1219a.jsp`, `z1219.jsp`             | Webroot and request logs        | Google-observed webshell candidate names; generated names will vary               |
| `127.0.0.1:8787`                                    | Operator or relay host          | Current fork's documented default management listener; configurable               |
| `127.0.0.1:8788`                                    | Operator or relay host          | Documented local recording proxy; not a mandatory target destination              |
| `mitmproxy-ca-cert.pem`                             | Operator-host filesystem        | Proxy-related certificate artifact; also occurs in legitimate tooling             |
| `exploration_nodes`, `exploration_anchors`          | Acquired PostgreSQL database    | Part of the documented graph schema; stronger when accompanied by task traces     |
| Proxy and CA variables in worker environments       | Process environment evidence    | Supporting evidence when correlated with the framework and its subprocesses       |

Generic curl, Python, Chromium, and Nmap fingerprints are deliberately not
presented as standalone IOCs. Neither are default ports sufficient for a
positive identification.

### Shared services are not blanket block targets

Google observed `webhook.site` endpoints carrying command output. The service
also has legitimate uses; preserve the full destination path, request context,
and sending process when investigating.

The FBI CSV lists outbound API destinations including `api.anthropic.com`,
`api.deepseek.com`, `open.bigmodel.cn`, and `api.x.ai`. These are shared model
service destinations, not malicious infrastructure by definition. Their
appearance does not prove ARTEX use or provider compromise.

No ARTEX binary hashes are supplied here. The selected evidence does not
establish a representative set across forks, rebuilt binaries, and modified
deployments.

## Hunting and detection priorities

The following are hunting hypotheses, not validated detection rules.
Thresholds and windows should be selected from local baselines and tested
against authorized assessment activity.

### Identity-first cloud investigation

Start with workload authentication rather than user sign-ins alone. Review
service-principal, managed-identity, and non-interactive activity where relevant
and available. Investigate new source infrastructure, unusual resource access,
and one source authenticating across multiple applications.

Then establish what happened after authentication:

1. Which resources and permissions did the identity enumerate?
2. Did it request credential-bearing configuration?
3. Did it retrieve secret values or only list metadata?
4. Did it add credentials, owners, grants, or privileged assignments?
5. Did it read or download business data?
6. Did activity continue through another identity or source?

Correlate using tenant, application, service-principal object, resource, and
request identifiers when available. Not every logging surface shares the same
identifier, and an IP-only join can mix unrelated activity.

Prioritize a chain of unusual authentication followed by credential access or
privilege changes over an isolated successful sign-in.

### Application mapping followed by access-control probes

Look for source-map, configuration, or API-documentation retrieval followed
soon afterward by requests to previously uncommon internal routes.
Raise the priority when that sequence also includes:

* Account registration followed by attempts to access another tenant's objects
* Repeated recovery or activation requests across identities
* Multiple SSO route variants and malformed callback parameters
* Related activity continuing across source changes after blocking
* A transition from repeated failures to successful sensitive operations

Normal browsers, search crawlers, testing systems, and vulnerability scanners
can retrieve many of the same resources. The relationship between requests and
their outcomes matters more than a single path.

### Adaptive cloud API activity

Investigate short sequences where the same identity changes API versions,
methods, or parameters after errors, particularly when successful follow-up
requests target credentials, roles, secrets, or execution features.

Retries are normal SDK behavior. Stronger evidence includes movement across
unrelated services, uncommon operations for that application, and sensitive
changes immediately after a corrected request.

### Server execution and payload delivery

On managed endpoints, investigate unexpected shell or interpreter execution
from web applications, application services, and database contexts.
Correlate download activity with file creation, execution, persistence, and
subsequent network connections.

For Java and MySQL environments, review unexpected changes to general-log
configuration, writes into web-accessible paths, new JSP files, compilation
errors, and requests to the resulting files. The reported abuse depends on
database privileges and filesystem conditions; log configuration alone is not
proof that a webshell executed.

For Windows database servers, correlate script execution and directory
enumeration with unusual outbound webhook traffic. Retain the sending process
and destination path rather than matching only the shared domain.

### Credential access and internal movement

Prioritize unusual service-ticket collection, suspected directory replication
from non-domain-controller systems, and privileged authentication followed by
remote execution.

Separate the stages. Kerberoasting is not proof of successful cracking.
A remote-management connection is not proof of command execution.
A failed pass-the-hash attempt is not successful lateral movement.

## Telemetry requirements and blind spots

| Evidence surface                    | Investigative use                                                     | Important limitation                                                     |
| ----------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Workload identity authentication    | Establish application identity, source, resource, and result          | User-only sign-in review misses app-only paths                           |
| Directory audit                     | Find credential, ownership, consent, and role changes                 | A change must be tied to its actor and affected object                   |
| Microsoft Graph activity            | Reconstruct API use after authentication                              | Availability depends on prior configuration and retention                |
| Cloud control-plane logs            | Review resource changes, role activity, and execution features        | Do not assume they contain every secret or object read                   |
| Key Vault and storage diagnostics   | Establish successful data-plane access and affected resources         | Missing diagnostics create an evidence gap, not evidence of no access    |
| Web, WAF, and application logs      | Link mapping, probing, account abuse, and successful requests         | A successful HTTP status does not establish the business outcome         |
| Endpoint process and file events    | Identify execution, payload staging, webshells, and follow-on tools   | The remote operator's ARTEX process may never exist on the endpoint      |
| DNS, proxy, and firewall logs       | Reconstruct egress and known infrastructure contact                   | Shared destinations and encrypted traffic limit specificity              |
| Acquired ARTEX platform evidence    | Recover task history, traces, configuration, and recorded traffic     | Available only when the relevant platform is accessible and preserved    |

Confirm ingestion and retention before deciding a hunt is negative.
Cloud-provider, application, and endpoint clocks should be normalized during
timeline construction. Preserve fine-grained timestamps; daily aggregation can
hide the short bursts that explain how the intrusion advanced.

A full set of records is rarely available. State which evidence surfaces are
missing and which conclusions those gaps prevent.

## MITRE ATT&CK assessment

Enterprise ATT&CK is the primary fit. The observed behavior concerns enterprise
applications, cloud identities, operating systems, and data. An LLM choosing
the next command does not by itself make the intrusion a prompt-injection or
model-poisoning attack.

The mappings below apply across the cited investigations, not to one complete
ARTEX intrusion. Technique IDs and names were checked against MITRE's public
pages. Confidence reflects the fit between reported behavior and the
technique, not independent verification of the underlying incident.

| Tactic or phase                         | Technique                                          | Confidence   | Evidence and boundary                                                          |
| --------------------------------------- | -------------------------------------------------- | ------------ | ------------------------------------------------------------------------------ |
| Reconnaissance                          | T1595 Active Scanning                              | High         | Internet-facing application mapping and probing reported by Wiz and Microsoft  |
| Initial Access                          | T1190 Exploit Public-Facing Application            | High         | Storm-3358 application exploitation; not every probe succeeded                 |
| Credential Access                       | T1110.003 Password Spraying                        | High         | Explicit Storm-0940 spray reporting; reported spray did not yield access       |
| Initial Access and Persistence          | T1078.004 Cloud Accounts                           | High         | Valid application identities used for cloud and downstream tenant access       |
| Persistence and Privilege Escalation    | T1098.001 Additional Cloud Credentials             | High         | Application credential additions reported in downstream activity               |
| Persistence and Privilege Escalation    | T1098.003 Additional Cloud Roles                   | High         | Reported privileged role changes; validate success per affected environment    |
| Execution                               | T1059.009 Cloud API                                | High         | Azure VM Run Command use in reported agentic credential-abuse activity         |
| Persistence                             | T1505.003 Web Shell                                | High         | Reported webshell deployment and working JSP execution                         |
| Credential Access                       | T1558.003 Kerberoasting                            | High         | Google reports service-ticket harvesting and an offline cracking interval      |
| Credential Access                       | T1003.006 DCSync                                   | High         | Google reports directory replication abuse and theft of domain key material    |
| Command and Control                     | T1105 Ingress Tool Transfer                        | High         | Microsoft reports agents downloading follow-on RATs                            |
| Collection                              | T1213 Data from Information Repositories           | High         | Reported database and collaboration-repository collection                      |
| Exfiltration                            | T1567.004 Exfiltration Over Webhook                | High         | Google reports directory command output sent to webhook endpoints              |

Public-repository secret discovery is discussed separately rather than forced
into a local credential-file sub-technique. No ATLAS technique is assigned
solely because the attacker used AI. The available material does not establish
prompt injection, model poisoning, or model theft as a general ARTEX behavior.
Suspected abuse of AI-service credentials also requires case-specific evidence
before mapping a successful AI-resource compromise.

## Incident response priorities

### Contain usable access

When evidence establishes credential exposure or unauthorized access:

1. Identify the affected identity, credentials, permissions, and accessible
   resources.
2. Revoke or rotate exposed credentials through the appropriate owner.
3. Disable the affected principal or integration when necessary and authorized,
   considering the operational impact.
4. Preserve identity configuration and relevant logs without delaying urgent
   containment.
5. Remove confirmed unauthorized credentials, grants, owners, roles, and
   identities.
6. Investigate secrets and resources reached through the original credential.

Deleting an enterprise application as the first action can destroy useful
configuration context and interrupt recovery workflows. Preserve evidence and
follow current vendor containment guidance.

Credential rotation does not necessarily invalidate every access token already
issued. Account for token lifetime and service-specific revocation behavior
when verifying containment.

### Scope the secondary access

Determine whether the intruder established access beyond the original entry
point. Review new application credentials, certificates, federated credentials,
accounts, role assignments, remote-access payloads, webshells, cloud instances,
and automation changes where supported by the incident.

If a readable secret store was accessed, assess the downstream credentials it
contained. A narrow rotation of the initial leaked secret may leave those
secondary credentials usable.

For suspected vendor-origin compromise, scope all relevant customer tenants
and trust relationships, including integrations that are no longer actively
used but retain permissions.

### Preserve evidence with operational value

Retain raw sign-ins, directory changes, cloud requests, application logs,
endpoint evidence, and object-level data access where available. Record
credential identifiers and validity windows without unnecessarily copying
secret values.

On an ARTEX operator or relay host, preserve the PostgreSQL data, worker traces,
recorded traffic, task configuration, local workspace, model endpoint
configuration, proxy certificates, and container or process evidence.
Handle this material as sensitive: it may contain victim data, recovered
credentials, and full request or response content.

### Verify containment

Containment is not demonstrated by the disappearance of one source IP.
Confirm that the original access no longer works, attacker-added access has
been removed, relevant secondary credentials have been addressed, and no
unauthorized activity continues through alternate identities or endpoints.

For affected backup or recovery integrations, verify restore capability as
part of recovery. Security remediation should not silently leave recovery
workflows broken.

## Hardening priorities

### Remove long-lived credential exposure

Use managed identities or appropriately scoped workload federation where
supported. Their benefit is reduced reliance on reusable static secrets, not
immunity from compromise of the workload itself.

Enable secret scanning and push protection where available. Scan repository
history and public exposure beyond the primary organization. Treat a publicly
exposed credential as compromised even after the commit is removed.

### Reduce application authority

Inventory application permissions, owners, credentials, and business purpose.
Remove unnecessary grants and stale integrations. Separate read-only
application access from credential management and role administration.

Apply controls appropriate to workload identities. Do not assume a user MFA
policy protects a client-credential authentication flow. Product licensing and
support boundaries, especially for third-party multi-tenant applications, must
be checked before relying on a particular policy.

### Restrict administrative and execution surfaces

Keep management interfaces, database administration, deployment endpoints,
and remote execution features away from untrusted networks where possible.
Constrain permissions for Run Command, publishing credentials, storage keys,
and equivalent administrative operations.

For internet-facing applications, address authorization checks, tenant
isolation, account recovery, SSRF, unsafe uploads, and exposed operational
configuration. Source-map removal alone is not an authorization control.

### Make response faster without making it reckless

Pre-authorize bounded actions for high-confidence conditions such as exposed
secrets or confirmed unauthorized privilege changes. Record the responsible
owner, rollback path, and service dependencies.

Do not automatically disable production identities because they used curl,
contacted a model API, or exceeded an untested request threshold.

### Use deception as a supplement

Microsoft reports testing decoys, tarpits, and fake-success surfaces against
agentic attacks. These can create useful signals and consume attacker effort.
They are not a substitute for access control, and their effectiveness should
be tested locally rather than assumed.

Any decoy credential must be isolated and incapable of reaching production
data. Do not introduce a real credential exposure in the name of detection.

## Confidence, unresolved questions, and limits

Confidence is high that ARTEX has been used in real intrusions and that
credential abuse, application trust, and rapid follow-on activity are central
defensive concerns. Multiple independent organizations report compatible
observations.

Confidence is lower when identifying a particular framework from target-side
traffic alone. Generic client fingerprints, continuous probing, and error
correction are not unique to ARTEX.

The following remain unresolved or case-dependent:

* The exact fork, build, model, prompts, and approval settings used in each
  reported intrusion
* The amount of human intervention behind individual automated sequences
* The current ownership and activity of historical infrastructure
* The complete victim count and extent of data theft across campaigns
* The full affected-application list where the October Microsoft prose and
  examples differ
* Whether future modified builds retain the documented network and host
  fingerprints

There is no basis in the reviewed evidence to claim a universal ARTEX zero-day,
a universal MFA bypass, or guaranteed end-to-end autonomous success.
Predictions about more capable future frameworks should not be presented as
already observed behavior.

## Conclusion

ARTEX makes familiar security failures cheaper to find and faster to exploit.
A credential that once required an operator to investigate manually can now
feed a sequence of permission checks, credential retrieval, and data access
with little delay.

Its current weakness is also visible: noisy probing, errors, changing payloads,
and administrative actions leave evidence. Effective defense connects that
evidence quickly and limits what a single compromised identity can reach.
The durable response is less trust, fewer reusable secrets, better
cross-surface visibility, and containment that completes before the next
successful branch.

## Sources

All sources below were accessed on November 24, 2026. Dates are included where
established by the reviewed publication. Project documentation reflects a
moving branch and is not pinned to a release or commit.

### Incident reporting and advisories

1. Microsoft Threat Intelligence and Microsoft Security Research.
   *AI-driven, large-scale nation-state campaign using ARTEX enables supply
   chain compromise*. October 21, 2026.
   <https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/>
2. Google Threat Intelligence Group and Mandiant.
   *ARTEX and Friends: Enter Agentic Offensive Frameworks*. October 31, 2026.
   <https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks>
3. Wiz Research.
   *ARTEX in the wild: Storm-0940 expands targeting of IT and software vendors*.
   <https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors>
4. Microsoft Threat Intelligence and Microsoft Security Research.
   *Threat actors use agentic AI tooling to find and abuse exposed secrets*.
   November 5, 2026.
   <https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/>
5. Microsoft Threat Intelligence.
   *ARTEX abuse expands as cybercriminals target financial sector*.
   November 6, 2026.
   <https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/>
6. CERT-EU.
   *From Penetration Testing to Cyber Threat: Beware of ARTEX*.
   November 5, 2026.
   <https://cert.europa.eu/blog/from-penetration-testing-to-cyber-threat-beware-of-artex/>
7. FBI Internet Crime Complaint Center.
   *Threat Overview of ARTEX Autonomous Penetration Testing Framework*.
   November 13, 2026. Publication listing verified; PDF body not extracted.
   <https://www.ic3.gov/CSA>
   <https://www.ic3.gov/CSA/2026/261113.pdf>
8. FBI Internet Crime Complaint Center.
   *FLASH-20261113-001 IOCs*. CSV accompanying the November 13 advisory;
   content reviewed directly, including its contextual-use warning.
   <https://www.ic3.gov/CSA/2026/261113.csv>

### Project documentation

1. ARTEX Global Edition. Public repository and README, including architecture,
   deployment defaults, and upstream provenance statements.
   <https://github.com/jiwoochris/artex-global>
   <https://raw.githubusercontent.com/jiwoochris/artex-global/main/README.md>
2. ARTEX Global Edition. *Defending Against and Detecting Autonomous AI Attacks*.
   Documentation of target-side and operator-side fingerprints.
   <https://raw.githubusercontent.com/jiwoochris/artex-global/main/docs/defense-en.md>

### MITRE technique definitions

* T1595 Active Scanning:
  <https://attack.mitre.org/techniques/T1595/>
* T1190 Exploit Public-Facing Application:
  <https://attack.mitre.org/techniques/T1190/>
* T1110.003 Password Spraying:
  <https://attack.mitre.org/techniques/T1110/003/>
* T1078.004 Cloud Accounts:
  <https://attack.mitre.org/techniques/T1078/004/>
* T1098.001 Additional Cloud Credentials:
  <https://attack.mitre.org/techniques/T1098/001/>
* T1098.003 Additional Cloud Roles:
  <https://attack.mitre.org/techniques/T1098/003/>
* T1059.009 Cloud API:
  <https://attack.mitre.org/techniques/T1059/009/>
* T1505.003 Web Shell:
  <https://attack.mitre.org/techniques/T1505/003/>
* T1558.003 Kerberoasting:
  <https://attack.mitre.org/techniques/T1558/003/>
* T1003.006 DCSync:
  <https://attack.mitre.org/techniques/T1003/006/>
* T1105 Ingress Tool Transfer:
  <https://attack.mitre.org/techniques/T1105/>
* T1213 Data from Information Repositories:
  <https://attack.mitre.org/techniques/T1213/>
* T1567.004 Exfiltration Over Webhook:
  <https://attack.mitre.org/techniques/T1567/004/>
