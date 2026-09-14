# Hard blocks are non-overridable

Accepted on 2026-09-14.

Chinese identity card numbers, bank card numbers, credentials and secrets, local absolute paths, configured sensitive terms, internal/customer/supplier organizations, internal project names, person names, precise addresses, and quasi-identifier combinations always use the local route. The first release intentionally does not offer placeholder authorization for these entities because their presence signals a high-risk workflow or leaves identifying context after a literal value is replaced.

Phone numbers and email addresses are handled separately as the only first-release placeholder-eligible entities. Authorization never overrides a hard block, including when the same request also contains an eligible contact value.
