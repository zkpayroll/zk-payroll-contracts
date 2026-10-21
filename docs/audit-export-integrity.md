# Audit Export Integrity Marker (#607)

Exported compliance summaries now carry a deterministic **integrity marker** so
external auditors and indexers can tell whether the metadata they received is
exactly what the contract produced, or whether any field was altered after the
export.

This documents the on-chain behavior in
`contracts/audit_module/src/lib.rs` and the SDK workflow around it.

## Motivation

`AuditModule::export_audit_summary` returns an `AuditMetadataSummary` to
external compliance tooling. Once that struct leaves the contract there is
nothing binding its fields together: a downstream system (or an intermediary)
could change a period bound or inflate a verification count and the tampered
export would be indistinguishable from a genuine one. The integrity marker adds
a checksum that the recipient can verify against the contract itself.

## What the marker is

Every export includes an `integrity_marker: BytesN<32>` field, computed on-chain
at export time as:

```
SHA-256(
    "zkpayroll_audit_export_v1" ||
    company_id (XDR) ||
    period_start (u64 LE) ||
    period_end (u64 LE) ||
    total_audit_entries (u32 LE) ||
    verification_pass_count (u32 LE) ||
    verification_fail_count (u32 LE) ||
    exported_at (u64 LE) ||
    exported_by (XDR)
)
```

The `zkpayroll_audit_export_v1` domain separator prevents a marker from being
confused with a digest computed for another purpose. Because **every** field of
the summary is bound, changing any one of them — including the exporter address
or the export timestamp — changes the marker.

Salary values are never part of the summary or the marker, so the export remains
privacy-safe.

## Verifying an export

**Entrypoint:** `AuditModule::verify_audit_export_integrity`

| Input | Type | Description |
|-------|------|-------------|
| `summary` | `AuditMetadataSummary` | The exported summary to verify |

| Result | Meaning | Suggested action |
|--------|---------|------------------|
| `Ok(true)` | The marker matches the summary fields — the export is intact. | Accept the export. |
| `Ok(false)` | The marker does not match — the export was altered after production. | Reject, re-export, and investigate the intermediary. |
| `Err(AuditError::IntegrityMarkerMissing)` | The summary has no marker (all-zero bytes). | Treat as malformed; re-export from the contract. |

A fresh export always verifies:

```rust
let summary = audit.export_audit_summary(&auditor, &company_id, &start, &end);
assert!(audit.verify_audit_export_integrity(&summary));
```

## Interpreting results

- The marker proves **integrity**, not **authenticity**: anyone can build a
  summary and compute a matching marker. Authenticity comes from obtaining the
  summary through `export_audit_summary` (which requires a valid, scoped view
  key) or from the on-chain `AuditSummaryExported` event.
- The marker is a pure function of the exported fields, so two exports of the
  same unchanged state produce the same marker.
- The verification entrypoint is read-only and permissionless — it reads no
  private payroll data and mutates no state, so it is safe to call from any
  integration.

## Tests

`contracts/audit_module/src/tests.rs` covers:

| Test | Path |
|------|------|
| `test_export_audit_summary_carries_verifiable_integrity_marker` | success — non-zero marker that verifies |
| `test_audit_export_integrity_detects_tampered_count` | failure — mutated count is rejected |
| `test_audit_export_integrity_detects_tampered_exporter` | failure — swapped exporter is rejected |
| `test_audit_export_integrity_rejects_missing_marker` | edge — all-zero marker returns `IntegrityMarkerMissing` |
| `test_audit_export_integrity_marker_is_deterministic` | edge — identical state yields identical markers |
