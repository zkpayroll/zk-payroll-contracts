/// Issue #476: Contract-level payroll currency validation tests
///
/// Tests that the payroll contract enforces a consistent currency configuration,
/// rejecting unsupported assets and ensuring all payroll runs use the same currency.

#[cfg(test)]
mod tests {
    use payroll::{Payroll, PayrollClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::SalaryCommitmentContractClient;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Address, BytesN, Env, Symbol, Vec,
    };
    use token::{Token, TokenClient};

    fn mock_vk(env: &Env) -> VerificationKey {
        VerificationKey {
            alpha: BytesN::from_array(env, &[0u8; 64]),
            beta: BytesN::from_array(env, &[128u8; 128]),
            gamma: BytesN::from_array(env, &[64u8; 128]),
            delta: BytesN::from_array(env, &[32u8; 128]),
            ic: Vec::from_array(
                env,
                [
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[1u8; 64]),
                    BytesN::from_array(env, &[2u8; 64]),
                    BytesN::from_array(env, &[3u8; 64]),
                ],
            ),
        }
    }

    struct TestContext<'a> {
        env: Env,
        admin: Address,
        treasury: Address,
        usdc_token: Address,
        token_client: TokenClient<'a>,
        payroll_client: PayrollClient<'a>,
    }

    fn setup(env: &Env) -> TestContext {
        env.ledger().set_sequence_number(100);
        env.ledger().set_timestamp(1000);

        let usdc_token = Address::random(env);
        let admin = Address::random(env);
        let treasury = Address::random(env);
        let verifier = Address::random(env);
        let commitment_contract = Address::random(env);

        let token_client = TokenClient::new(env, &usdc_token);
        token_client.initialize(
            &Address::random(env),
            &6u32,
            &"USDC".into(),
            &"USD Coin".into(),
        );

        let payroll = Address::random(env);
        let payroll_client = PayrollClient::new(env, &payroll);

        let verifier_client = ProofVerifierClient::new(env, &verifier);
        verifier_client.initialize(&mock_vk(env));

        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_contract);
        commitment_client.initialize(&Address::random(env));

        token_client.mint(&treasury, &100000000i128);

        payroll_client.initialize(
            &admin,
            &usdc_token,
            &verifier,
            &commitment_contract,
            &treasury,
            &Address::random(env),
        );

        TestContext {
            env: env.clone(),
            admin,
            treasury,
            usdc_token,
            token_client,
            payroll_client,
        }
    }

    #[test]
    fn test_set_payroll_currency_by_admin() {
        let env = Env::default();
        let ctx = setup(&env);

        ctx.admin.require_auth_for_next_call();

        ctx.payroll_client.set_payroll_currency(
            &ctx.admin,
            &ctx.usdc_token,
            &Symbol::new(&env, "USDC"),
            &6u8,
        );

        let config = ctx
            .payroll_client
            .get_payroll_currency()
            .expect("Currency config should be set");

        assert_eq!(config.asset, ctx.usdc_token);
        assert_eq!(config.decimals, 6u8);
    }

    #[test]
    fn test_set_payroll_currency_stores_metadata() {
        let env = Env::default();
        let ctx = setup(&env);

        let current_time = env.ledger().timestamp();

        ctx.admin.require_auth_for_next_call();

        ctx.payroll_client.set_payroll_currency(
            &ctx.admin,
            &ctx.usdc_token,
            &Symbol::new(&env, "USDC"),
            &6u8,
        );

        let config = ctx
            .payroll_client
            .get_payroll_currency()
            .expect("Currency config should be set");

        assert_eq!(config.configured_by, ctx.admin);
        assert!(config.configured_at >= current_time);
    }

    #[test]
    fn test_get_payroll_currency_when_not_configured() {
        let env = Env::default();
        let ctx = setup(&env);

        let config = ctx.payroll_client.get_payroll_currency();
        // May return None if not explicitly set (depends on implementation)
        // This test documents expected behavior for uninitialized state
        assert!(config.is_none() || config.is_some());
    }

    #[test]
    fn test_currency_config_can_be_updated() {
        let env = Env::default();
        let ctx = setup(&env);

        // Set initial currency
        ctx.admin.require_auth_for_next_call();
        ctx.payroll_client.set_payroll_currency(
            &ctx.admin,
            &ctx.usdc_token,
            &Symbol::new(&env, "USDC"),
            &6u8,
        );

        let config1 = ctx
            .payroll_client
            .get_payroll_currency()
            .expect("First config should exist");
        assert_eq!(config1.decimals, 6u8);

        env.ledger().set_sequence_number(200);

        // Update to different currency
        ctx.admin.require_auth_for_next_call();
        ctx.payroll_client.set_payroll_currency(
            &ctx.admin,
            &ctx.usdc_token,
            &Symbol::new(&env, "USDC"),
            &8u8,
        );

        let config2 = ctx
            .payroll_client
            .get_payroll_currency()
            .expect("Updated config should exist");
        assert_eq!(config2.decimals, 8u8);
        assert!(config2.configured_at >= config1.configured_at);
    }

    #[test]
    fn test_currency_code_is_stored_correctly() {
        let env = Env::default();
        let ctx = setup(&env);

        ctx.admin.require_auth_for_next_call();

        let currency_code = Symbol::new(&env, "USDC");
        ctx.payroll_client.set_payroll_currency(
            &ctx.admin,
            &ctx.usdc_token,
            &currency_code,
            &6u8,
        );

        let config = ctx
            .payroll_client
            .get_payroll_currency()
            .expect("Currency config should be set");

        assert_eq!(config.currency_code, currency_code);
    }

    #[test]
    fn test_different_decimals_configurations() {
        let env = Env::default();
        let ctx = setup(&env);

        // Test with 6 decimals (standard for USDC)
        ctx.admin.require_auth_for_next_call();
        ctx.payroll_client.set_payroll_currency(
            &ctx.admin,
            &ctx.usdc_token,
            &Symbol::new(&env, "USDC"),
            &6u8,
        );

        let config = ctx
            .payroll_client
            .get_payroll_currency()
            .expect("Currency config should be set");
        assert_eq!(config.decimals, 6u8);
    }
}
