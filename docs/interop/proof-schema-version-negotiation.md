# Proof Schema Version Negotiation — Issue #111

Explains how clients and contracts handle evolving proof schema versions so
that integrations do not silently break as proof formats change.

---

## Background

ZK Payroll uses Groth16 proofs over BN254. The on-chain verifier checks:

```
public_inputs.len() + 1 == vk.ic.len()
```

Any change to the number or layout of public inputs constitutes a **schema
version change** and requires coordinated rollout across clients and contracts.

---

## Schema Version Registry

Each schema version is identified by a `u32` integer. The table below is the
canonical source of truth. Increment it when the public-input set or proof
byte layout changes.

| Version | Public inputs (ordered) | Proof byte layout | Status |
|---------|------------------------|-------------------|--------|
| `1` | `[commitment: BytesN<32>, amount: BytesN<32>]` | `pi_a[64] \|\| pi_b[128] \|\| pi_c[64]` = 256 bytes | **Current / active** |
| `0` | `[commitment, nullifier, recipient_hash]` (legacy 3-input) | Same 256-byte layout | Deprecated — rejected by v1 verifier |

> To add a new version: append a row, deploy a new `VerificationKey` for
> that version, and update clients before the old VK is rotated out.

---

## Metadata Expectations

### Client → Contract (proof submission)

Clients must include a `proof_schema_version` value alongside each proof
submission. The recommended transport is a dedicated field in the off-chain
payload (e.g. JSON RPC body); on-chain the version is **implicit** — the
verifier derives it from `vk.ic.len()`:

```
expected_inputs = vk.ic.len() - 1
```

If the submitted public inputs do not match `expected_inputs`, the contract
returns `false` from `verify_payment_proof` immediately (no panic, no state
change).

### Contract → Client (version advertisement)

Clients may call `get_verification_key()` on the `proof_verifier` contract
to read the active `VerificationKey` and compute the expected input count:

```rust
let vk = proof_verifier.get_verification_key();
let expected_public_inputs: u32 = vk.ic.len() - 1;
```

Use this count to validate proof generation parameters before submitting a
transaction, avoiding wasted gas on a predictable rejection.

---

## Compatibility Rules

| Client version | Contract VK version | Result |
|---------------|---------------------|--------|
| v1 client (2 inputs) | v1 VK (ic.len = 3) | ✅ Accepted |
| v0 client (3 inputs) | v1 VK (ic.len = 3) | ❌ Rejected — input count mismatch |
| v1 client (2 inputs) | v0 VK (ic.len = 4) | ❌ Rejected — input count mismatch |
| v1 client (2 inputs) | v2 VK (future, ic.len = N) | ❌ Rejected unless N = 3 |

**Rule**: a client MUST generate proofs against the VK currently stored
on-chain. There is no runtime negotiation — mismatches are hard rejections.

---

## Rejection Behaviour

When `verify_payment_proof` receives public inputs that do not match the
stored VK:

1. The function returns `false` immediately.
2. No state is written (no nullifier recorded, no payment made).
3. The transaction does not panic; the caller receives a `false` result.
4. The batch executor treats a `false` verification as a failed proof and
   reverts the entire batch (see `payment_executor` atomicity guarantee).

Clients SHOULD surface this as a distinct error code (`ProofSchemaRejected`)
rather than a generic payment failure to aid debugging.

---

## Upgrade Procedure

Follow this sequence when rolling out a new proof schema version:

1. **Circuit change**: Update the Circom circuit and regenerate the `.zkey`
   and `verification_key.json` artefacts via the trusted setup process
   documented in `CONTRIBUTING.md`.

2. **Client update**: Release updated client libraries that generate proofs
   against the new circuit. Include the new `proof_schema_version` in
   metadata.

3. **Shadow period**: Run both the old and new client generators in parallel
   against testnet. Confirm the new proofs pass verification against the new
   VK and fail against the old one.

4. **VK deployment**: The `proof_verifier` admin calls `initialize_verifier`
   on a **newly deployed** verifier contract instance with the new VK.
   (The current contract is single-initialisation; do not attempt to overwrite
   an existing VK — the contract will panic.)

5. **Contract address update**: Update `payment_executor` / `payroll`
   `ContractAddresses.verifier` to point to the new verifier instance.

6. **Client cutover**: Switch production clients to use the new verifier
   address. Retire the old client version.

7. **Deprecation window**: Keep the old verifier deployed (read-only) for
   30 days to allow audit queries against historical proofs.

---

## Client Integration Checklist

Before upgrading a client integration to a new proof schema:

- [ ] Read `vk.ic.len()` from the target network's verifier contract.
- [ ] Confirm circuit artefacts match the expected `ic.len()` count.
- [ ] Generate a test proof and call `verify` on testnet — confirm `true`.
- [ ] Run existing integration tests against the new verifier address.
- [ ] Update the `proof_schema_version` metadata field in client payloads.
- [ ] Coordinate cutover timing with the contract admin.

---

## Unsupported Combinations

The following combinations are explicitly unsupported and will always be
rejected:

- Any proof with `public_inputs.len() == 0` (no inputs at all).
- Any proof where `public_inputs.len() + 1 > vk.ic.len()` (too many inputs).
- Any proof where `public_inputs.len() + 1 < vk.ic.len()` (too few inputs).
- Proofs serialised with a different byte layout than `pi_a[64] || pi_b[128] || pi_c[64]`.
- Public inputs using `i128` raw bytes instead of the canonical `BytesN<32>`
  big-endian zero-padded encoding.

---

## Related Resources

- `contracts/proof_verifier/src/lib.rs` — on-chain verifier implementation
- `circuits/payment.circom` — current circuit (v1 schema)
- `circuits/generate_proof.js` — proof generation reference implementation
- `CONTRIBUTING.md` — trusted setup and circuit compilation guide
- `docs/architecture/commitment-state-storage-layout-13.md` — storage context
