---
title: "Encrypted, but Still Exposed: The Lesson of Compaction Smuggling"
description: "How an OpenAI API flaw turned conversation compaction into a path for protected reasoning disclosure."
ms.date: 2026-11-02
ms.topic: concept
keywords:
  - AI security
  - compaction smuggling
  - reasoning disclosure
  - model distillation
estimated_reading_time: 10
---

## A conversation feature crossed a security boundary

Encryption can protect information while it is stored or transmitted. It cannot, on its own, guarantee that a system will handle that information safely after decrypting it.

A reported OpenAI API vulnerability called **compaction smuggling** illustrates that distinction. Xint researchers say they recovered protected reasoning by routing it through conversation compaction, a feature intended to keep long-running AI interactions manageable.

According to Xint, OpenAI confirmed the issue, deployed a fix on October 23, 2026, and awarded a $6,000 bounty.

The finding deserves attention, but not exaggeration. It was not a demonstrated break of encryption, theft of model weights, or compromise of every customer's conversation. It exposed a different problem: restrictions on sensitive information did not consistently follow that information through a connected AI workflow.

## Why AI systems preserve hidden state

Reasoning models generate internal tokens as they work through a problem. The final answer is only part of that process.

OpenAI's API can preserve internal reasoning in opaque encrypted artifacts. An application can pass those artifacts back during later interactions, allowing the service to maintain continuity without giving the application direct access to the raw reasoning.

Compaction addresses another practical limit. Conversations grow, and eventually their accumulated history becomes too large or expensive to carry forward.

The service can condense useful state into a smaller representation. OpenAI documents encrypted compaction items as opaque artifacts that preserve relevant context and reasoning for subsequent turns.

Both capabilities serve legitimate purposes. The vulnerability reportedly emerged where they overlapped.

## The detour that mattered

Earlier research had shown that portable encrypted reasoning could create disclosure opportunities. Providers subsequently introduced protections against known extraction routes.

Xint found a different path.

Rather than sending a protected reasoning artifact directly to another model, the researchers reportedly influenced the compaction stage to preserve reasoning inside a compaction artifact. Another model then rendered information from that artifact as readable output.

The protected information crossed the boundary indirectly.

That is the central lesson: blocking one route is not enough if another supported feature can move the same information into a less-protected form.

In the researchers' account, the compaction process had access to decrypted reasoning while also accepting caller-controlled instructions. A context-management function could therefore be repurposed into an information-transfer function.

The report also describes a formatting change that helped evade classifiers. The important defensive point is not the particular formatting choice. It is that controls must account for information moving between representations, not only inspect the most obvious form.

## Why this was not an encryption break

The researchers did not report recovering encryption keys or defeating a cipher.

The provider's service already had permission to interpret the encrypted state. The apparent failure occurred when that authorized processing allowed protected content to reach a caller-visible channel.

An analogy is a secure document that remains locked during delivery but is then handed to a processing service that exposes its contents through an export feature.

The lock can work as designed while the workflow still violates confidentiality.

For AI systems, the relevant security boundary includes every component that can interpret sensitive state: compaction, summarization, routing, downstream generation, and other transformations.

## The evidence has an important limit

Xint reported that two different downstream models produced identical recovered text. The examples contained terse phrasing, false starts, and self-corrections consistent with reasoning traces.

Those observations support the researchers' interpretation, but they do not prove perfect reconstruction.

The researchers did not possess the original hidden plaintext for comparison. They therefore could not establish that every recovered token matched the original reasoning.

Matching downstream outputs show consistency in the rendering stage. They do not prove that the earlier compaction stage preserved everything without alteration.

The responsible conclusion is that protected reasoning disclosure was credibly reported, while exact token-for-token recovery remains unproven.

## Why protected reasoning has value

A final answer shows a result. Intermediate reasoning may also contain alternate approaches, revisions, and unsuccessful attempts.

That material can be useful when training another model to imitate the original system's behavior. Unauthorized access therefore raises concerns about model distillation and loss of control over proprietary outputs.

Distillation itself is not inherently malicious. It is a legitimate machine-learning technique when performed with appropriate authorization and data rights.

The concern here is obtaining protected material by circumventing the provider's controls.

The compaction-smuggling disclosure did not demonstrate a trained replacement model or quantify the value of the recovered traces. Those remain potential consequences rather than measured outcomes.

## Separate the vulnerability from the wider threat landscape

OpenAI has separately described coordinated attempts to extract protected reasoning. Related academic work also examined weaknesses involving portable encrypted reasoning across providers.

That context helps explain why this class of issue matters.

It does not prove that attackers used Xint's exact compaction-smuggling method. Nor should sensitive-data findings from separate research be presented as losses caused by this vulnerability.

The distinction matters because a threat report can become misleading when it combines a real vulnerability, a separate campaign, and unrelated exposure figures into one apparent incident.

## What enterprise users should do

The disclosed demonstration used the researchers' own API requests. It did not establish unauthorized access to another organization's conversations.

Enterprise users should therefore avoid treating the headline as evidence of a universal customer-data breach.

The practical response is to review how applications handle opaque AI state:

* Restrict access to reasoning and compaction artifacts.
* Avoid placing those artifacts in public repositories or broadly accessible debugging bundles.
* Reduce unnecessary logging and retention.
* Keep state from unrelated users and sessions separated.
* Seek remediation assurance for the service paths actually used.
* Investigate concrete exposure evidence before initiating credential rotation or breach-response procedures.

An artifact that an application cannot read is not automatically harmless. It may still carry sensitive information that another authorized component can interpret.

The researchers' use of `store=false` also underscores a separate point: storage settings and disclosure controls solve different problems. A request can avoid a particular persistence mode while still entering a vulnerable processing workflow.

## What AI providers should learn

As AI platforms add memory, compaction, routing, and agent orchestration, security boundaries become workflow-wide concerns.

Testing only the final answer or the most obvious extraction prompt leaves gaps. Providers also need to ask whether protected information can move through another feature and emerge with weaker restrictions.

The governing principle is straightforward:

> Protection must follow the information, not merely the original artifact or endpoint.

That means preserving appropriate authorization and sensitivity rules through transformations, enforcing them at downstream consumers, and testing that legitimate continuity still works without enabling disclosure.

## The bottom line

Xint reports that the specific issue has been fixed. The wider lesson remains.

Compaction smuggling shows how a useful conversation feature can become a disclosure path when one processing stage trusts information differently from another.

Encryption is necessary in many designs, but it does not replace end-to-end control over how sensitive information is interpreted, transformed, and exposed.

For increasingly complex AI systems, that is a security requirement worth testing before the next feature ships.

## Sources and editorial notes

This article is based on public-source research, not independent exploitation or fix validation. References appear only in this section.

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
