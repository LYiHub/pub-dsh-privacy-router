# Chinese PII detection is hybrid and fails local

Accepted on 2026-09-14.

The first release combines deterministic recognizers, local Chinese named-entity recognition, and user or enterprise dictionaries. Regex handles phone numbers, email addresses, identity cards, and bank cards; local NER handles names, organizations, addresses, job titles, and projects; dictionaries cover custom sensitive terms and internal, customer, supplier, and project names. Job titles are evaluated through dictionaries and quasi-identifier co-occurrence.

An available local model may perform structured NER, but Presidio is an optional later adapter rather than a required dependency. Low-confidence, conflicting, unavailable, malformed, or failed semantic detection returns `unknown` and uses the local route. Only phone numbers and email addresses may proceed to the separate placeholder authorization flow; all other detected entities remain local.

Classifier output follows the same fail-local rule. A complete tool-call is trusted only with a `tool-calls` finish state. A `max-tokens` finish may recover only a natural truncation inside the `reason` string; every other finish state or malformed/trailing payload returns `unknown`.
