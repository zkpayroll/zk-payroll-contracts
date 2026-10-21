# Payroll Upload Recovery Checkpoints (#782)

Contract-layer upload checkpoints provide an admin-authorized, privacy-safe
cursor for payroll data submitted in chunks. The contract stores no uploaded
rows, employee identities, salaries, or proof material; upload data remains
off-chain.

## Lifecycle

1. `begin_payroll_upload_checkpoint(admin, upload_id, batch_root, total_chunks)`
   opens a unique upload. Both digests must be non-zero and `total_chunks`
   must be positive.
2. `record_payroll_upload_progress(admin, upload_id, uploaded_chunks)` advances
   the absolute cursor by exactly one chunk. Repeating the current cursor is an
   idempotent acknowledgement; skipped, regressing, over-total, or terminal
   progress is rejected. Reaching `total_chunks` marks the upload completed.
3. `mark_payroll_upload_failed(admin, upload_id)` records an interruption and
   preserves the cursor.
4. `resume_payroll_upload(admin, upload_id)` reopens only a failed upload and
   returns its saved cursor so the caller can continue at the next chunk.
5. `get_payroll_upload_checkpoint(upload_id)` provides a read-only status view.

Only the stored contract admin may create or change checkpoints. Upload IDs are
unique; completed records cannot be changed, while failed records can be
resumed. Use a fresh ID to represent a replacement upload.

The checkpoint cursor is operational metadata reported by the authorized
uploader. It does not store or validate chunk contents. Callers must bind the
upload ID and `batch_root` to their own immutable upload payload and verify the
returned cursor before submitting additional chunks.

## Events

The `payroll_upload_started`, `payroll_upload_progress`,
`payroll_upload_completed`, `payroll_upload_failed`, and
`payroll_upload_resumed` events carry only the opaque upload ID, batch-root
digest, and aggregate chunk counts.
