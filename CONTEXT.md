# DSH Privacy Router

DSH Privacy Router decides whether a Harness turn may use a cloud model while preserving the user's privacy boundary. It exists to keep sensitive, uncertain, and context-dependent work local while allowing explicitly approved low-risk text to use a cloud model.

## Language

**Local Route**:
An execution path where the original request and its required private context remain on a trusted local model provider.
_Avoid_: offline path, private model

**Cloud Route**:
An execution path where only a rebuilt and approved text context is sent to a remote model provider.
_Avoid_: public model, remote fallback

**Hard Block**:
A local-only decision that user authorization cannot override. The first release hard-blocks identity cards, bank cards, credentials, secrets, local paths, configured sensitive terms, internal/customer/supplier organizations, internal project names, person names, precise addresses, and identifying combinations.
_Avoid_: sensitive warning, soft denial

**PII Entity**:
A concrete data element that identifies, or can contribute to identifying, a person, organization, location, account, or credential.
_Avoid_: secret, redaction token

**Placeholder-Eligible Entity**:
A lower-risk PII entity that may be replaced by a stable placeholder after explicit, scoped user authorization. In the first release, this set contains only phone numbers and email addresses.
_Avoid_: approved secret, removable PII

**Redaction Map**:
The local-only association between placeholders in a cloud-safe text and the original values. It is never sent to a cloud provider.
_Avoid_: token table, substitution log

**Authorization Scope**:
The boundary of a user's placeholder approval, including the concrete entity values or entity categories and whether it applies to one request or one session. The supported choices are the current values only, the entity categories for the current session, or denial. There is no workspace-wide, global, or permanent scope.
_Avoid_: global permission, permanent consent

**Authorization Card**:
The DSH user question that presents a placeholder decision for eligible entities. It shows entity types, counts, and masked previews; it never shows complete values and cannot authorize hard blocks.
_Avoid_: chat command, permanent consent dialog

**One-Shot Authorization**:
The property that an authorization card is raised through `ctx.userQuestions.ask()` as a transient interaction and leaves no persistent state afterwards. DSH exposes no persistent authorization-status surface and no revocation API for these cards (`ctx.dshAuth.logout()` is OAuth-only and unrelated), so the first release has no authorization status indicator and no revocation UI.
_Avoid_: revocable consent, persistent permission

**Quasi-Identifier Combination**:
A group of weak identifiers that becomes identifying when the values appear together, such as a name, rare job title, customer organization, and internal project name.
_Avoid_: standalone title, generic organization name

**Cloud-Safe Context**:
The rebuilt conversation content that remains after hard-blocked material is withheld and placeholder-eligible entities are redacted, generalized, or removed.
_Avoid_: original history, sanitized prompt

**Rescan**:
A repeated policy scan of the rebuilt cloud-safe context immediately before a cloud request is sent. Cloud history is rescanned during assembly, and an independent final rescan gates the outbound request.
_Avoid_: second classification, final review

**Full-Payload NER Scan**:
The entity analysis run over the complete planned cloud text after authorization and placeholder redaction succeed: the rebuilt approved history (`cloudMessages`) concatenated with the sanitized current messages, rather than only the current user message. A hard entity, a dangerous quasi-identifier combination, or an uncertain or invalid result downgrades the turn to `unknown` and keeps it local. It is a gate, not a source of authorization prompts: authorization cards trigger only from current-user-message entities, and history can block a cloud request without raising a card. Only hard-entity metadata (type and count) is stored for this guard, never values or hashes.
_Avoid_: current-turn NER, history authorization prompt

**NER Error**:
A failure of the local NER request (transport error, abort, or unexpected exception). The turn is recorded as `method: entity-analysis`, `reason: ner-error`, marked uncertain, classified `unknown`, and stays local. NER cannot be disabled by configuration and a NER failure is never silently skipped.
_Avoid_: NER bypass, skippable analysis

**Auxiliary Purpose**:
A non-user-facing request such as session-title or compaction. It follows the same local privacy boundary: a known trusted local route is required, and an unknown route is blocked.
_Avoid_: metadata bypass, background exemption

**Internal Organization**:
An organization from a local internal, customer, supplier, or partner dictionary whose mention may reveal a private business relationship.
_Avoid_: company, enterprise

**Precise Address**:
A location description fine-grained enough to identify a person, residence, office, device, or exact point of interest.
_Avoid_: city, region

**Trusted Provider**:
A provider whose ID matches `trustedProviders` exactly or starts with an entry in `trustedProviderPrefixes` (default prefix `local-ai-`). Trust is granted by ID, not by network location: it proves nothing about whether the endpoint is physically on localhost, and a provider named `local-ai-foo` pointing at a remote host is still trusted. Administrators must only assign `local-ai-*` IDs to genuinely local endpoints.
_Avoid_: verified local endpoint, localhost check
