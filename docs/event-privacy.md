# Privacy-safe payroll event payloads

Payroll events are an integration boundary, not a payroll statement. Event
topics and data must remain safe to index publicly and must never disclose
salary, proof material, document contents, or private employee metadata.

## Allowed payloads

| Event family | Public fields | Prohibited fields |
| --- | --- | --- |
| Contract initialization | contract domain, administrator address | credentials, private keys |
| Pause and unpause | affected category, operation timestamp | reason text, operator secrets |
| Treasury accounting | company identifier, asset address, amount, operation kind | employee address, salary, bank details |
| Payroll run lifecycle | opaque run id, batch count, total amount, lifecycle state | per-employee amounts, proofs, employee list |
| Salary commitment lifecycle | employee address, commitment status, commitment hash | salary amount, raw commitment, identity documents |
| Retention lifecycle | company id, opaque record id, record type, eligibility/prune time | archived record contents, audit evidence |
| Verification and audit | opaque request id, result/status, evidence hash | evidence contents, personal data |

Amounts are emitted only at aggregate treasury or run level. Hashes are
commitments, never serialized source documents. Consumers must treat unknown
fields as non-contractual and ignore them so future schema additions do not
force disclosure or break older indexers.

## Consumer rules

1. Index topics for filtering; do not infer private records from event order.
2. Store hashes and opaque identifiers as references, not as recoverable data.
3. Redact event payloads before forwarding them to logs, notifications, or
   analytics systems.
4. A new event or field must be reviewed against this table and tested with a
   payload fixture before release.
