# Placeholder authorization is value-based and session-scoped
Accepted on 2026-09-14.

The safest default approval is for a concrete phone number or email value in the current request. The DSH authorization card also offers a session-category choice and an explicit denial. The session choice is held in memory for a default twelve-hour TTL and applies only to the current session.

There is no workspace-wide, global, or permanent authorization. A chat message or prompt cannot act as an authorization card. Hard-blocked entities never enter this flow.

Redaction maps are local-only and use opaque placeholders. They are scoped to the current request or session authorization and are never sent to a cloud provider. Expiry stops future cloud use of the affected context but cannot technically retake content already sent to a cloud provider.

Consequences accepted by this decision:

The session-category scope lives only in a process-local Map with a 12-hour TTL (`authorizationTtlMs`, default 43200000). It is not persisted to the session event log or to disk, and it is lost when DSH restarts; previously authorized categories must be authorized again after a restart. This is intentional fail-closed behavior.

The authorization card is one-shot. It is raised through `ctx.userQuestions.ask()`, which is transient: DSH exposes no persistent authorization-status surface and no revocation API for it (`ctx.dshAuth.logout()` is OAuth-only and unrelated). There is therefore no persistent authorization status indicator and no revocation UI in this release; a session-category authorization cannot be withdrawn manually and can only expire via TTL or a DSH restart. This is recorded as a known limitation.

Authorization cards trigger only from entities found in the current user message. The full-payload NER scan over the planned cloud text (rebuilt approved history plus sanitized current messages) acts as a gate that can downgrade a turn to `unknown` and keep it local, but history never raises an authorization card itself.
