//! Multi-stage payroll approval rollback protections tests — issue #414.
//!
//! # Coverage
//! | Test | Scenario |
//! |------|----------|
//! | `test_multi_stage_approval_flow_success` | Sequential approvals advance stage and lock upon completion |
//! | `test_stale_approval_reused_rejected` | Stale content hash submission panics with "Stale approval reused" |
//! | `test_amend_draft_rolls_back_partial_approvals` | Protected field edits roll back approvals to 0 and emit rollback event |
//! | `test_duplicate_signer_approval_rejected` | Duplicate approval from same signer panics |
//! | `test_approval_after_lock_rejected` | Approval attempt after draft lock panics |
use payroll::{
    signing::compute_protected_content_hash, ApprovalInvalidationError, Payroll, PayrollClient,
    PayrollRunIdError,
};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, BytesN, Env, Symbol, TryFromVal, Vec,
};
use token::Token;

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

struct Ctx {
    env: Env,
    admin: Address,
    _treasury: Address,
    payroll_id: Address,
}

impl Ctx {
    fn payroll(&self) -> PayrollClient<'_> {
        PayrollClient::new(&self.env, &self.payroll_id)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    let verifier_id = env.register(ProofVerifier, ());
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register(SalaryCommitmentContract, ());
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    let token_id = env.register(Token, ());

    let payroll_id = env.register(Payroll, ());
    let payroll = PayrollClient::new(&env, &payroll_id);

    payroll.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    Ctx {
        env,
        admin,
        _treasury: treasury,
        payroll_id,
    }
}

#[test]
fn test_multi_stage_approval_flow_success() {
    let ctx = setup();
    let draft_id = 100u64;
    let total_amount = 50_000i128;
    let emp_count = 10u32;
    let obligation_root = BytesN::from_array(&ctx.env, &[0x11; 32]);
    let metadata_hash = BytesN::from_array(&ctx.env, &[0x22; 32]);

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &total_amount,
        &emp_count,
        &obligation_root,
        &metadata_hash,
        &2u32,
    );

    assert_eq!(approval.current_approvals, 0);
    assert_eq!(approval.required_approvals, 2);
    assert!(!approval.is_locked);

    let hash = approval.protected_content_hash;

    let signer1 = Address::generate(&ctx.env);
    let st1 = ctx
        .payroll()
        .submit_draft_approval(&signer1, &draft_id, &hash);
    assert_eq!(st1.current_approvals, 1);
    assert_eq!(st1.current_stage, 1);
    assert!(!st1.is_locked);

    let signer2 = Address::generate(&ctx.env);
    let st2 = ctx
        .payroll()
        .submit_draft_approval(&signer2, &draft_id, &hash);
    assert_eq!(st2.current_approvals, 2);
    assert_eq!(st2.current_stage, 2);
    assert!(st2.is_locked);
}

#[test]
#[should_panic(expected = "Stale approval reused: protected fields changed")]
fn test_stale_approval_reused_rejected() {
    let ctx = setup();
    let draft_id = 101u64;
    let root = BytesN::from_array(&ctx.env, &[0x11; 32]);
    let meta = BytesN::from_array(&ctx.env, &[0x22; 32]);

    let _approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root,
        &meta,
        &2u32,
    );

    // Provide an incorrect / stale protected hash
    let stale_hash = BytesN::from_array(&ctx.env, &[0xFF; 32]);
    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &stale_hash);
}

#[test]
fn test_amend_draft_rolls_back_partial_approvals() {
    let ctx = setup();
    let draft_id = 102u64;
    let root1 = BytesN::from_array(&ctx.env, &[0x11; 32]);
    let meta1 = BytesN::from_array(&ctx.env, &[0x22; 32]);

    let _approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &20_000i128,
        &4u32,
        &root1,
        &meta1,
        &2u32,
    );
    let hash1 = compute_protected_content_hash(&ctx.env, 20_000i128, 4u32, &root1, &meta1);

    let signer1 = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer1, &draft_id, &hash1);

    let state_before = ctx.payroll().get_draft_approval_state(&draft_id).unwrap();
    assert_eq!(state_before.current_approvals, 1);

    // Edit draft: protected total_amount changes from 20_000 to 25_000
    let root2 = BytesN::from_array(&ctx.env, &[0x33; 32]);
    let meta2 = BytesN::from_array(&ctx.env, &[0x44; 32]);
    let rolled_back = ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &25_000i128,
        &5u32,
        &root2,
        &meta2,
    );

    assert_eq!(rolled_back.current_approvals, 0);
    assert_eq!(rolled_back.current_stage, 0);
    assert!(!rolled_back.is_locked);
    assert_ne!(rolled_back.protected_content_hash, hash1);

    // Verify approvals_rolled_back event was emitted
    let events = ctx.env.events().all();
    let rollback_event = events.events().iter().find(|event| {
        let soroban_sdk::xdr::ContractEventBody::V0(body) = &event.body;
        {
            if let Some(val) = body.topics.get(1) {
                if let Ok(sym) = Symbol::try_from_val(&ctx.env, val) {
                    return sym == Symbol::new(&ctx.env, "approvals_rolled_back");
                }
            }
        }
        false
    });
    assert!(rollback_event.is_some());
}

#[test]
#[should_panic(expected = "Duplicate approval from same signer")]
fn test_duplicate_signer_approval_rejected() {
    let ctx = setup();
    let draft_id = 103u64;
    let root = BytesN::from_array(&ctx.env, &[0x11; 32]);
    let meta = BytesN::from_array(&ctx.env, &[0x22; 32]);

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root,
        &meta,
        &2u32,
    );

    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &approval.protected_content_hash);

    // Duplicate approval by same signer
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &approval.protected_content_hash);
}

#[test]
#[should_panic(expected = "Draft is locked")]
fn test_approval_after_lock_rejected() {
    let ctx = setup();
    let draft_id = 104u64;
    let root = BytesN::from_array(&ctx.env, &[0x11; 32]);
    let meta = BytesN::from_array(&ctx.env, &[0x22; 32]);

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root,
        &meta,
        &1u32, // Only 1 required
    );

    let signer1 = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer1, &draft_id, &approval.protected_content_hash);

    // Draft is now locked. Attempting a 2nd approval should panic.
    let signer2 = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer2, &draft_id, &approval.protected_content_hash);
}

// ── Checked approval-invalidation errors (#986) ──────────────────────────────
// These pin the additive `*_checked` entrypoint: typed, payload-free errors
// and no state change on every rejection path.

type CheckedAmend = Result<
    Result<payroll::signing::MultiStageApproval, soroban_sdk::ConversionError>,
    Result<ApprovalInvalidationError, soroban_sdk::InvokeError>,
>;

fn checked_amend(
    ctx: &Ctx,
    admin: &Address,
    draft_id: u64,
    amount: i128,
    count: u32,
    root: &BytesN<32>,
    meta: &BytesN<32>,
) -> CheckedAmend {
    ctx.payroll()
        .try_amend_draft_rollback_checked(admin, &draft_id, &amount, &count, root, meta)
}

#[test]
fn test_checked_amend_success_invalidates_prior_approvals() {
    let ctx = setup();
    let draft_id = 200u64;
    let root = BytesN::from_array(&ctx.env, &[0x11; 32]);
    let meta = BytesN::from_array(&ctx.env, &[0x22; 32]);

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin, &draft_id, &10_000i128, &2u32, &root, &meta, &2u32,
    );
    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &approval.protected_content_hash);
    assert_eq!(
        ctx.payroll()
            .get_draft_approval_state(&draft_id)
            .unwrap()
            .current_approvals,
        1
    );

    let new_root = BytesN::from_array(&ctx.env, &[0x33; 32]);
    let updated = checked_amend(
        &ctx, &ctx.admin, draft_id, 20_000i128, 2u32, &new_root, &meta,
    )
    .unwrap()
    .unwrap();

    assert_ne!(updated.protected_content_hash, approval.protected_content_hash);
    assert_eq!(updated.current_approvals, 0);
    assert_eq!(updated.current_stage, 0);
    assert!(!updated.is_locked);
    assert_eq!(updated.signers.len(), 0);
}

#[test]
fn test_checked_amend_rejects_without_state_change() {
    let ctx = setup();
    let draft_id = 201u64;
    let root = BytesN::from_array(&ctx.env, &[0x11; 32]);
    let meta = BytesN::from_array(&ctx.env, &[0x22; 32]);

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin, &draft_id, &10_000i128, &2u32, &root, &meta, &2u32,
    );
    let before = ctx.payroll().get_draft_approval_state(&draft_id).unwrap();

    // Non-positive amount.
    let err = checked_amend(&ctx, &ctx.admin, draft_id, 0i128, 2u32, &root, &meta).unwrap_err();
    assert_eq!(err, Ok(ApprovalInvalidationError::InvalidTotalAmount));

    // Non-admin caller (explicit check, independent of mocked auth).
    let intruder = Address::generate(&ctx.env);
    let err = checked_amend(&ctx, &intruder, draft_id, 20_000i128, 2u32, &root, &meta).unwrap_err();
    assert_eq!(err, Ok(ApprovalInvalidationError::Unauthorized));

    // Unchanged revision is reported explicitly as a no-op.
    let err = checked_amend(
        &ctx, &ctx.admin, draft_id, 10_000i128, 2u32, &root, &meta,
    )
    .unwrap_err();
    assert_eq!(err, Ok(ApprovalInvalidationError::NoRevisionChange));

    // No approval tracker for this draft.
    let err = checked_amend(&ctx, &ctx.admin, 9999u64, 10_000i128, 2u32, &root, &meta).unwrap_err();
    assert_eq!(err, Ok(ApprovalInvalidationError::ApprovalNotInitialized));

    let after = ctx.payroll().get_draft_approval_state(&draft_id).unwrap();
    assert_eq!(before.protected_content_hash, after.protected_content_hash);
    assert_eq!(before.current_approvals, after.current_approvals);
    assert_eq!(before.signers.len(), after.signers.len());
    assert_eq!(approval.protected_content_hash, after.protected_content_hash);
}

// ── Safe run-identifier errors (#991) ────────────────────────────────────────

#[test]
fn test_checked_run_id_rejects_reserved_and_missing_without_panic() {
    let ctx = setup();
    let admin = ctx.admin.clone();

    let err = ctx
        .payroll()
        .try_get_payroll_run_checked(&admin, &u64::MAX)
        .unwrap_err();
    assert_eq!(err, Ok(PayrollRunIdError::ReservedRunId));

    let err = ctx
        .payroll()
        .try_get_payroll_run_checked(&admin, &12345u64)
        .unwrap_err();
    assert_eq!(err, Ok(PayrollRunIdError::RunNotFound));
}
