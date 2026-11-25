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

## Redaction guarantees

Payroll events and the errors they surface are redacted at the source. The
following data must never appear in an event payload, an error message, or a
log line emitted by the payroll contracts:

- salary amounts, rates, or any per-employee compensation figure;
- employee identifiers (addresses, names, account numbers) outside the
  explicitly allowed commitment-lifecycle fields above;
- proof bytes, raw commitments, or any serialized document contents.

Errors report an opaque error code and, where useful, an opaque identifier
(run id, request id, record id). They never echo the offending input. This
applies equally to validation failures, state-transition rejections, and
recovery paths.

### Settlement recovery event

The settlement recovery event follows the same rules. It carries only the
opaque run id, the recovery outcome, and an evidence hash. It does not include
the recovered amounts, the affected employee list, or any proof material, so
it is safe to index and forward to downstream systems.

### Enforcement

Focused tests in `contracts/payroll/tests/` assert these guarantees for
success, failure, and boundary cases: they check that emitted events and error
results contain none of the prohibited salary, employee, or proof data. Any
new event or error path must add a matching redaction test before release.

## Consumer rules

1. Index topics for filtering; do not infer private records from event order.
2. Store hashes and opaque identifiers as references, not as recoverable data.
3. Redact event payloads before forwarding them to logs, notifications, or
   analytics systems.
4. A new event or field must be reviewed against this table and tested with a
   payload fixture before release.
