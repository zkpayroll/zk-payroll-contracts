/// Multi-stage payroll approval rollback protections tests — issue #414.
///
/// # Coverage
/// | Test | Scenario |
/// |------|----------|
/// | `test_multi_stage_approval_flow_success` | Sequential approvals advance stage and lock upon completion |
/// | `test_stale_approval_reused_rejected` | Stale content hash submission panics with "Stale approval reused" |
/// | `test_amend_draft_rolls_back_partial_approvals` | Protected field edits roll back approvals to 0 and emit rollback event |
/// | `test_duplicate_signer_approval_rejected` | Duplicate approval from same signer panics |
/// | `test_approval_after_lock_rejected` | Approval attempt after draft lock panics |
use payroll::{signing::compute_protected_content_hash, Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, BytesN, Env, Symbol, TryFromVal, TryIntoVal, Vec,
};
use token::{Token, TokenClient};

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
    treasury: Address,
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

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
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
        treasury,
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

    let approval = ctx.payroll().init_draft_approval(
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
    let rollback_event = events.iter().find(|(_, topics, _)| {
        if let Some(val) = topics.get(1) {
            if let Ok(sym) = Symbol::try_from_val(&ctx.env, &val) {
                return sym == Symbol::new(&ctx.env, "approvals_rolled_back");
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
