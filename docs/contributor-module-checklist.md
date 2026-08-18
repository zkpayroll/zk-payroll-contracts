# Contributor Checklist: Adding or Expanding a Contract Module — Issue #95

Use this checklist when introducing a new Soroban contract or extending an
existing one. It covers the minimum bar for a reviewable PR. Keep it updated
as repo standards evolve.

---

## 1. Interface Design

- [ ] **Trait defined** — if the module exposes a public interface, define it
  as a Rust `trait` (see `PayrollRegistryTrait` in `payroll_registry/src/lib.rs`
  for the pattern). This makes the interface explicit and independently testable.

- [ ] **Entry-point signatures reviewed** — all public entry-points have the
  minimal parameter set needed. Avoid bundling unrelated concerns into one call.

- [ ] **Error enum defined** — use a `#[contracterror]` enum with `u32`
  discriminants instead of `panic!()` or raw strings for all recoverable error
  conditions. Follow the `PaymentError` pattern in `payment_executor/src/lib.rs`.

- [ ] **No raw `unwrap()` or `panic!()` in entry-points** — use `.expect("reason")`
  only for truly unrecoverable invariants; use `Result` return types for everything
  else. See the Code Standards table in [CONTRIBUTING.md](../CONTRIBUTING.md#code-standards).

---

## 2. Authorization

- [ ] **Every state-mutating entry-point calls `env.require_auth()`** — there are
  no exceptions. Check all `pub fn` implementations that write to storage.

- [ ] **Admin role is set at init time, not hard-coded** — admin addresses are
  passed to the initialiser and stored in `Persistent` storage. Hard-coded
  addresses are not acceptable.

- [ ] **One-time init is guarded** — the initialiser checks for an existing
  admin/state key and panics with `"Already initialized"` if called twice.

- [ ] **Role separation is explicit** — if the module introduces multiple roles
  (e.g., admin vs. payroll operator), document them in a block comment at the
  top of `lib.rs` following the pattern in `salary_commitment/src/lib.rs`.

---

## 3. Events

- [ ] **All significant state changes emit an event** — at minimum: creation,
  update, and deletion of any primary record. Pause/unpause transitions always
  emit events.

- [ ] **Event topics follow the taxonomy** — topic naming must align with
  [docs/monitoring/event-taxonomy.md](./monitoring/event-taxonomy.md).
  Use `PascalCase` for single-symbol topics (e.g., `"CommitmentUpdated"`);
  use a two-symbol tuple `("contract_name", "action")` for the `payroll`
  facade pattern.

- [ ] **Event taxonomy doc updated** — add the new event(s) to
  `docs/monitoring/event-taxonomy.md` under the appropriate category
  (`ONB`, `FND`, `EXE`, `AUD`, `SEC`) with full field documentation.

- [ ] **Payload examples updated** — if the event introduces a new data shape,
  add a sample to [docs/payload-examples.md](./payload-examples.md).

- [ ] **No sensitive values in events** — salary amounts, blinding factors, and
  private keys must never appear in event data. Commitments (Poseidon hashes)
  are acceptable; raw salary values are not.

---

## 4. Storage

- [ ] **`DataKey` enum is used for all storage keys** — no inline `Symbol`
  or string keys. Follow the `DataKey` pattern used in every existing contract.

- [ ] **Storage type is appropriate** — use `Persistent` for records that must
  survive ledger expiry (commitments, nullifiers, payment records). Use
  `Temporary` only for short-lived nonces. Document the choice in a comment
  if it is not obvious.

- [ ] **TTL strategy documented** — if the module writes `Persistent` entries,
  note how TTL is extended (on write, on payment execution, or via an off-chain
  keeper). See `docs/architecture/commitment-state-storage-layout-13.md` for
  the recommended pattern.

- [ ] **Individual keys, not bulk vectors** — do not store collections of
  records under a single key. Use per-record keys (e.g.,
  `DataKey::Payment(employee, period)`) to avoid Soroban read/write budget
  failures on large datasets. See the architecture doc above for rationale.

---

## 5. Tests

- [ ] **At least one unit test per public entry-point** — happy path covered.
  Place tests in `src/tests.rs` (for larger modules) or an inline `#[cfg(test)]`
  module following the existing contract patterns.

- [ ] **Auth rejection tested** — at least one test verifies that an
  unauthorized caller is rejected (use `env.mock_auths` with the wrong address
  or no auths, and assert the call panics or returns an error).

- [ ] **Double-init tested** — if the module has a one-time initialiser, test
  that calling it twice panics with `"Already initialized"`.

- [ ] **Error variants tested** — for each `#[contracterror]` variant, at least
  one test triggers that variant and asserts the correct error is returned.

- [ ] **Tests pass cleanly**: `cargo test -p <crate_name>` exits with zero
  failures before opening a PR.

---

## 6. Documentation

- [ ] **Rustdoc on all public items** — every `pub fn`, `pub struct`, and
  `pub enum` has a doc comment. One sentence is enough for obvious items;
  include a note on authorization requirements and preconditions for any
  entry-point that is not self-evident.

- [ ] **Role documentation block at top of `lib.rs`** — if the module has
  multiple roles, add a block comment explaining each role and what it is
  allowed to do. Follow the pattern in `salary_commitment/src/lib.rs`.

- [ ] **README or architecture doc linked** — if the module introduces
  non-obvious design decisions (storage layout, cross-contract dependencies,
  TTL policy), link or add a doc in `docs/architecture/`.

- [ ] **Contributor checklist updated** — if this PR introduces a new pattern
  or standard, update this checklist so the next contributor benefits.

---

## 7. Security Review

- [ ] **Replay protection in place** — if the module processes proofs or
  one-time tokens, nullifiers are recorded in `Persistent` storage *before*
  the effect is applied (checks-effects-interactions order).

- [ ] **No cross-contract reentrancy path** — review any cross-contract calls
  (e.g., calls to `salary_commitment`, `proof_verifier`, or token contracts)
  and confirm state writes happen before those calls where possible.

- [ ] **Fuzz target considered** — if the entry-point processes variable-length
  binary inputs (proofs, commitments), consider adding a fuzz target in
  `fuzz/fuzz_targets/`. See `fuzz/README.md` for setup.

- [ ] **Security tests in dedicated file** — for payment or proof-handling
  modules, add a `tests/security_tests.rs` file following the pattern in
  `contracts/payment_executor/tests/security_tests.rs`.

- [ ] **`cargo audit` passes** — run `cargo audit` from the workspace root
  before opening the PR. No new unreviewed advisories.

---

## 8. Release Readiness

- [ ] **Deployment order documented** — if the new module has initialisation
  dependencies on other contracts, update the deployment order in
  [docs/ops/preflight-deployment-checklist.md](./ops/preflight-deployment-checklist.md).

- [ ] **Rollback considered** — review
  [docs/ops/rollback-checklist.md](./ops/rollback-checklist.md) and confirm
  whether the new module introduces any state that would complicate a rollback
  (e.g., append-only records, cross-contract pointers that callers store).
  Document any rollback constraints in the PR description.

- [ ] **WASM size within limits** — `wc -c target/wasm32-unknown-unknown/release/<crate>.wasm`
  must be under 64 KB after `stellar contract build`.

---

## Related Resources

| Reference | Path |
|-----------|------|
| CONTRIBUTING.md | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Event taxonomy | [docs/monitoring/event-taxonomy.md](./monitoring/event-taxonomy.md) |
| Event severity mappings | [docs/monitoring/event-severity-mappings.md](./monitoring/event-severity-mappings.md) |
| Storage layout architecture | [docs/architecture/commitment-state-storage-layout-13.md](./architecture/commitment-state-storage-layout-13.md) |
| Preflight deployment checklist | [docs/ops/preflight-deployment-checklist.md](./ops/preflight-deployment-checklist.md) |
| Rollback checklist | [docs/ops/rollback-checklist.md](./ops/rollback-checklist.md) |
| Proof schema version negotiation | [docs/interop/proof-schema-version-negotiation.md](./interop/proof-schema-version-negotiation.md) |
| Incident response playbook | [docs/incident-response-playbook.md](./incident-response-playbook.md) |
| Fuzz targets README | [fuzz/README.md](../fuzz/README.md) |

---

*Closes Issue [#95](https://github.com/zkpayroll/zk-payroll-contracts/issues/95)*
