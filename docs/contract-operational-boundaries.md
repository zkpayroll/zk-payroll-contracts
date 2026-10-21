# Contract Operational Boundaries

This document records the contract-facing rules for the three assigned follow-up areas.

## Payroll timezone boundaries

Contract timestamps are ledger timestamps and are interpreted as UTC seconds. Callers must convert local payroll dates to UTC before submitting metadata or querying a period. Period ranges are inclusive at both boundaries, and a reversed range must be rejected before any state lookup or mutation.

The contract must never infer a timezone from a display label or client locale. Off-chain clients should include the normalized UTC range in the committed payroll metadata so the same period can be reconstructed during reconciliation.

## Failed payout retry diagnostics

A failed payout should expose enough metadata for an operator to decide whether a retry is safe without exposing salary values. The diagnostic record should identify the company, employee, payroll period, failure category, retryability, and the ledger timestamp. Proof bytes, salary amounts, and private commitment material remain excluded.

Retry handling must preserve idempotency: a failed attempt may be retried only while the payroll state is retryable, and a successful nullifier or payment record must never be replayed.

## Salary policy change impact analysis

Policy changes should be evaluated against the committed policy version and the affected payroll period before execution. Impact reporting should expose policy-version transitions, affected employee count, and aggregate direction or range, while keeping individual salary values private.

A policy update should be treated as a new version. Existing payroll runs remain bound to their original policy commitment, and a run must record the policy version used during approval and execution so auditors can compare the intended and applied rules.