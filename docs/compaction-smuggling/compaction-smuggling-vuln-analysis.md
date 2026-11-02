---
title: "Encrypted, but Still Exposed: The Lesson of Compaction Smuggling"
description: "Technical analysis of protected reasoning disclosure across OpenAI reasoning, compaction, and downstream model boundaries."
ms.date: 2026-11-02
ms.topic: concept
keywords:
  - AI security
  - compaction smuggling
  - reasoning disclosure
  - information flow security
  - model distillation
estimated_reading_time: 10
---

## A state transformation became a disclosure path

**Compaction smuggling** is a reported confidentiality failure in the OpenAI Responses API workflow. Xint researchers describe moving protected reasoning from `gpt-5.6-sol` through conversation compaction, then using `gpt-4.1` and `gpt-4o` to render information from the resulting artifact as readable text.

The distinction is between permission to *carry state forward* and permission to *disclose that state*. An authenticated caller could possess an encrypted reasoning artifact for continuity without being authorized to inspect its plaintext. The reported transformation preserved access to the information but did not preserve equivalent disclosure restrictions.

According to Xint, OpenAI confirmed the issue, deployed an undisclosed fix on October 23, 2026, and awarded a $6,000 bounty. The supplied research report does not independently establish the fix implementation, deployment coverage, or post-fix regression results.

### Technical scope

| Property             | Publicly reported scope                                               |
| -------------------- | --------------------------------------------------------------------- |
| Entry surface        | Authenticated API use involving reasoning and conversation compaction  |
| Reasoning producer   | `gpt-5.6-sol`                                                          |
| Downstream consumers | `gpt-4.1` and `gpt-4o`                                                 |
| Caller control       | Researcher-owned tasks, compaction instructions, request sequencing    |
| Affected property    | Confidentiality of protected reasoning                                |
| Demonstrated access  | Reasoning associated with the researchers' own requests                |
| Version coverage     | No comprehensive affected-model or configuration range established     |
| Vulnerability IDs    | No CVE, authoritative CVSS vector, or CWE mapping identified            |

No separate victim interaction was needed in the own-request demonstration. That does not establish authentication bypass, access to another tenant's state, or universal exposure across model snapshots and hosting arrangements.

## The data model and its trust boundary

Reasoning models distinguish internal reasoning tokens from the final answer returned to an application. OpenAI supports preserving reasoning in opaque encrypted artifacts that an application can return in subsequent requests. The service can interpret those artifacts; the caller is not thereby entitled to read the underlying reasoning.

Conversation compaction addresses context growth by replacing accumulated conversation state with a smaller representation that preserves information needed for later turns. OpenAI documents encrypted compaction items as carrying relevant context and reasoning.

Both artifact types can therefore transport information that is not ordinary caller-visible text. Encryption protects the representation outside authorized processing, but the compactor and downstream model still participate in the information-access boundary.

An appropriate design invariant is:

```text
CarryForward(caller, protected_state) does not imply
Disclose(caller, protected_state)

Transform(protected_state) must preserve its disclosure restrictions.
```

This is an analytical security requirement, not a description of OpenAI's internal policy language. Artifact possession, permission to process an artifact, and permission to disclose its contents are separate authorization decisions.

## Reconstructing the reported processing chain

The source describes a three-stage sequence, without requiring a cryptographic attack:

1. A reasoning model processes a researcher-controlled task and returns protected reasoning in an opaque artifact.
2. Compaction processes that state with access to decrypted reasoning while accepting caller-controlled instructions about what to preserve.
3. A different model consumes the resulting encrypted compaction item and renders reasoning-like content into a caller-visible response.

The important intermediate object is the compaction item. The researchers did not merely replay the original reasoning artifact into another model.

```text
Researcher-controlled task
          |
          v
gpt-5.6-sol
          |
          v
Opaque protected reasoning artifact
          |
          v
Compaction on the originating model <--- Caller-controlled instructions
          |
          v
Encrypted compaction item
          |
          v
gpt-4.1 / gpt-4o
          |
          v
Caller-visible reasoning-like text
```

According to Xint, earlier mitigations restricted direct cross-model reasoning replay. Compaction reportedly avoided that restriction because the transformation ran on the model that generated the reasoning. The resulting compaction item remained consumable by other models.

The path therefore changed the *artifact class* before changing the *consumer*. A control applied only to the original reasoning-item route would not necessarily cover equivalent information arriving through a compaction item.

The researchers also reported an output-format transformation that helped evade classifiers. The source does not establish that every classifier or representation was vulnerable. The narrower engineering concern is that equivalent information may receive different treatment after its representation changes.

## Root cause: disclosure policy did not survive transformation

The public evidence supports an architectural assessment, not a source-code diagnosis. It does not identify a faulty function, encryption mode, key-management defect, or specific missing authorization check.

### Caller influence met privileged plaintext access

The compaction stage reportedly combined two capabilities: access to protected reasoning and acceptance of caller-supplied instructions. This resembles a confused-deputy pattern: a component authorized to process sensitive state can be influenced to move that state toward a channel the caller can read.

The necessary boundary is not a blanket prohibition on compaction instructions. It is a restriction on what those instructions can cause the compactor to preserve or expose when the input contains protected material.

### Changing the container did not change the sensitivity

A reasoning artifact and a compaction item serve different workflow purposes. Moving information between them should not grant new disclosure rights.

Conceptually, the failure was a loss of protection semantics across a transformation. A defensible implementation must retain sensitivity, ownership, and permitted-use constraints in a form consumers can enforce. This is a recommended property, not evidence that OpenAI implemented or omitted any particular metadata scheme.

### The downstream consumer completed the disclosure

The final model reportedly rendered information that the originating reasoning path was intended to keep hidden. Protecting only the producer is therefore insufficient: transformers and consumers must enforce compatible restrictions.

The cryptography could function correctly throughout this sequence. The service legitimately interpreted the encrypted state, transformed it, and later emitted information through a normal output channel. Confidentiality failed during authorized processing rather than through demonstrated key recovery or ciphertext decryption by the caller.

## What the token counts establish

The supplied report records one example with:

* 405 reasoning tokens
* A 612-token compaction item
* 609 tokens in each of two rendered outputs

Xint reported that `gpt-4.1` and `gpt-4o` produced identical recovered text. The examples included terse intermediate phrasing, false starts, and self-corrections consistent with reasoning traces. The method reportedly worked at every reasoning-effort setting the researchers tested, not necessarily every setting or deployment available.

These observations support consistent rendering of information carried by the compaction artifact. They do not establish lossless extraction of the original reasoning.

The researchers lacked the original hidden plaintext for comparison. Without that reference, neither equal downstream outputs nor token counts establish token-for-token fidelity. The larger compaction item could include formatting overhead or transformed content; its size is not a measurement of how much original reasoning survived.

Removing the original task reduces the likelihood that downstream models merely solved it again, but does not conclusively exclude reconstruction or paraphrasing. The supported conclusion is credible protected-reasoning disclosure with unresolved fidelity, not independently verified recovery of every original token.

## Impact without conflating separate incidents

The demonstrated property is unauthorized visibility into protected reasoning associated with researcher-controlled API requests. Confidentiality is the primary concern; the described flow did not demonstrate modification of provider models, service disruption, or infrastructure compromise.

Unauthorized distillation is a plausible follow-on risk. Intermediate reasoning can contain decisions, rejected approaches, and corrections that final answers omit. However, the disclosure did not demonstrate a trained student model, measure resulting capability gains, or quantify extraction cost at campaign scale.

Exposure of confidential application data is also conditional. It would depend on what the state contains, who can obtain or submit it, and the authorization context of the affected processing route. No cross-customer conversation breach was established.

OpenAI's separate reporting on coordinated distillation attempts and the related "Stealing Reasoning Traces from Proprietary LLM APIs" research provide context. Neither establishes that malicious actors used this exact compaction route. Exposure figures and attribution from those investigations should not be transferred to this disclosure.

## Detection requires workflow correlation

The source provides no validated detection rule, tenant schema, or malicious infrastructure indicators. The following are engineering hypotheses for investigation, not production-ready signatures.

### Correlate generation, compaction, and model switching

Where authorized metadata is available, correlate requests by application session and order them by time. Investigate repeated sequences that generate protected reasoning, compact it, and then invoke a different model with the resulting state.

Useful telemetry includes request and session identifiers, operation type, model identifier, timestamps, artifact lineage, and authorization context. These are proposed observability fields, not claimed OpenAI response fields or existing log columns.

Legitimate agents compact history and change models. A model switch alone is not evidence of exploitation. Repetition, unusual state-transfer patterns, and task context are necessary to assess intent.

### Track artifact movement without logging the artifact

An application-controlled lineage record can associate state with its originating user and session. A privacy-reviewed keyed fingerprint can help correlate reuse without placing raw opaque artifacts in general-purpose logs.

Reuse across unrelated users or sessions warrants investigation as an authorization or isolation issue. It does not, by itself, prove compaction-smuggling exploitation.

Where prompt or output inspection is lawful and necessary, repeated requests to expose hidden state can provide additional context. Restrict access and retention: creating a detection pipeline should not create a new repository of protected material.

## Defensive controls and regression criteria

### Application owners

Treat reasoning and compaction artifacts as sensitive conversation state, even when your application cannot read them.

* Inventory artifact storage, exports, debug traces, and support bundles
* Restrict artifact access and minimize retention
* Validate user and session association before accepting state for continuation
* Keep unrelated users' state isolated throughout application workflows
* Obtain remediation assurance for the service and hosting routes actually used
* Initiate credential rotation or incident response when exposure evidence warrants it

The researchers used `store=false`. That setting is not a mitigation for the reported processing flaw: persistence settings do not enforce what a service may disclose while interpreting supplied state.

### Model and platform providers

The following are proposed controls and tests, not descriptions of the undisclosed October 23 fix:

1. Preserve disclosure restrictions when reasoning becomes compaction state or another intermediate representation.
2. Validate ownership, context, purpose, and model compatibility wherever protected artifacts enter a workflow.
3. Prevent caller-controlled transformation instructions from authorizing protected-content disclosure.
4. Apply equivalent restrictions to downstream consumers, alternate output representations, and streamed responses.
5. Test direct replay and multi-stage transformation paths across supported producer-consumer combinations and reasoning-effort settings.
6. Verify that legitimate continuation and compaction still retain the task context they are designed to preserve.
7. Verify relevant hosted and partner routes rather than assuming remediation coverage is identical.

Provider-authorized regression tests need a trusted reference for protected state. With such a reference, evaluators can check whether prohibited content survives into caller-visible output rather than relying only on model refusals or matching downstream text. Tests must also cover paraphrased or reformatted disclosure: preventing exact string matches alone is not sufficient.

No reproduction or post-fix validation was performed for this article. No customer-installable patch is identified for the hosted-service issue.

## The bottom line

Compaction smuggling is an information-flow failure across a producer, a privileged transformer, and a downstream consumer. Encrypting intermediate artifacts does not establish that every subsequent use respects the original confidentiality boundary.

The practical invariant is that changing an artifact's representation must not expand the caller's right to read its contents. That property needs end-to-end verification across the workflow, not only testing at the original reasoning endpoint.

## Sources and editorial notes

This analysis follows the supplied Defender-Hunting-Packs report and its attributed findings, with a research cutoff of November 2, 2026. It is not independent exploitation, source-code review, or fix validation. References appear only in this section.

1. Xint. Original compaction-smuggling research, including the reported fix, bounty, and fidelity limitation.
   <https://xint.io/blog/compaction-smuggling-reasoning-traces>
2. Cybersecurity News. "Researchers Exploit OpenAI API Flaw to Extract Hidden GPT-5.6 Reasoning Traces."
   <https://cybersecuritynews.com/researchers-exploit-openai-api-flaw/>
3. OpenAI. Compaction documentation.
   <https://developers.openai.com/api/docs/guides/compaction>
4. OpenAI. Reasoning documentation.
   <https://developers.openai.com/api/docs/guides/reasoning>
5. OpenAI. "Disrupting a coordinated model distillation campaign." Related threat context, not proof of use of this exact technique.
   <https://openai.com/index/disrupting-a-coordinated-model-distillation-campaign/>
6. Panfilov et al. "Stealing Reasoning Traces from Proprietary LLM APIs." Related research, initially submitted August 10, 2026.
   <https://arxiv.org/abs/2608.09867>
7. Defender-Hunting-Packs. Supplied compaction-smuggling vulnerability report, including the model sequence, token counts, scope limitations, and proposed defensive checks.
   <https://github.com/rahul0216/Defender-Hunting-Packs/blob/main/research-reports/vulnerability-reports/compaction-smuggling-vulnerability-report.md>
