#![no_std]

#[allow(unused_imports)]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingOperatorRotation {
    pub new_operator: Address,
    pub proposed_by: Address,
    pub proposed_at: u64,
}

#[contracttype]
pub enum DataKey {
    Paused,
    Operator,
    PendingOperator,
}

#[cfg(feature = "contract")]
#[contract]
pub struct PauseManager;

#[cfg(feature = "contract")]
#[contractimpl]
impl PauseManager {
    pub fn initialize(e: Env, operator: Address) {
        if e.storage().persistent().has(&DataKey::Operator) {
            panic!("Already initialized");
        }
        e.storage().persistent().set(&DataKey::Operator, &operator);
        e.storage().persistent().set(&DataKey::Paused, &false);
        payroll_events::emit_pause_manager_initialized(&e, operator);
    }

    pub fn pause(e: Env) {
        let operator: Address = e
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized");
        operator.require_auth();
        e.storage().persistent().set(&DataKey::Paused, &true);
        payroll_events::emit_paused(&e);
    }

    pub fn unpause(e: Env) {
        let operator: Address = e
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized");
        operator.require_auth();
        e.storage().persistent().set(&DataKey::Paused, &false);
        payroll_events::emit_unpaused(&e);
    }

    pub fn is_paused(e: Env) -> bool {
        e.storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn propose_operator_rotation(e: Env, current_operator: Address, new_operator: Address) {
        let operator: Address = e
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized");
        if current_operator != operator {
            panic!("Unauthorized: caller is not the current operator");
        }
        current_operator.require_auth();

        if e.storage().persistent().has(&DataKey::PendingOperator) {
            panic!("A pending operator rotation already exists");
        }

        let proposal = PendingOperatorRotation {
            new_operator: new_operator.clone(),
            proposed_by: current_operator.clone(),
            proposed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PendingOperator, &proposal);

        e.events().publish(
            (
                Symbol::new(&e, "PauseManager"),
                Symbol::new(&e, "op_proposed"),
            ),
            (current_operator, new_operator),
        );
    }

    pub fn accept_operator_rotation(e: Env, new_operator: Address) {
        let proposal: PendingOperatorRotation = e
            .storage()
            .persistent()
            .get(&DataKey::PendingOperator)
            .expect("No pending operator rotation");

        if new_operator != proposal.new_operator {
            panic!("Unauthorized: caller is not the proposed operator");
        }
        new_operator.require_auth();

        e.storage()
            .persistent()
            .set(&DataKey::Operator, &new_operator);
        e.storage().persistent().remove(&DataKey::PendingOperator);

        e.events().publish(
            (
                Symbol::new(&e, "PauseManager"),
                Symbol::new(&e, "op_rotated"),
            ),
            new_operator,
        );
    }

    pub fn cancel_operator_rotation(e: Env, current_operator: Address) {
        let operator: Address = e
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized");
        if current_operator != operator {
            panic!("Unauthorized");
        }
        current_operator.require_auth();

        if !e.storage().persistent().has(&DataKey::PendingOperator) {
            panic!("No pending operator rotation to cancel");
        }
        e.storage().persistent().remove(&DataKey::PendingOperator);

        e.events().publish(
            (
                Symbol::new(&e, "PauseManager"),
                Symbol::new(&e, "op_cancelled"),
            ),
            current_operator,
        );
    }

    pub fn get_pending_operator_rotation(e: Env) -> Option<PendingOperatorRotation> {
        e.storage().persistent().get(&DataKey::PendingOperator)
    }

    pub fn get_operator(e: Env) -> Address {
        e.storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized")
    }
}

#[cfg(not(feature = "contract"))]
pub struct PauseManagerClient<'a>(pub &'a Env, pub &'a Address);

#[cfg(not(feature = "contract"))]
impl<'a> PauseManagerClient<'a> {
    pub fn new(env: &'a Env, contract_id: &'a Address) -> Self {
        Self(env, contract_id)
    }

    fn empty_args(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Val> {
        soroban_sdk::Vec::new(env)
    }

    fn single_arg<A: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(
        env: &Env,
        a: A,
    ) -> soroban_sdk::Vec<soroban_sdk::Val> {
        let mut v = soroban_sdk::Vec::new(env);
        v.push_back(a.into_val(env));
        v
    }

    fn two_args<
        A: soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
        B: soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
    >(
        env: &Env,
        a: A,
        b: B,
    ) -> soroban_sdk::Vec<soroban_sdk::Val> {
        let mut v = soroban_sdk::Vec::new(env);
        v.push_back(a.into_val(env));
        v.push_back(b.into_val(env));
        v
    }

    pub fn initialize(&self, operator: &Address) {
        let _: () = self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "initialize"),
            Self::single_arg(self.0, operator.clone()),
        );
    }

    pub fn pause(&self) {
        let _: () = self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "pause"),
            Self::empty_args(self.0),
        );
    }

    pub fn unpause(&self) {
        let _: () = self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "unpause"),
            Self::empty_args(self.0),
        );
    }

    pub fn is_paused(&self) -> bool {
        self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "is_paused"),
            Self::empty_args(self.0),
        )
    }

    pub fn propose_operator_rotation(&self, current_operator: &Address, new_operator: &Address) {
        let _: () = self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "propose_operator_rotation"),
            Self::two_args(self.0, current_operator.clone(), new_operator.clone()),
        );
    }

    pub fn accept_operator_rotation(&self, new_operator: &Address) {
        let _: () = self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "accept_operator_rotation"),
            Self::single_arg(self.0, new_operator.clone()),
        );
    }

    pub fn cancel_operator_rotation(&self, current_operator: &Address) {
        let _: () = self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "cancel_operator_rotation"),
            Self::single_arg(self.0, current_operator.clone()),
        );
    }

    pub fn get_pending_operator_rotation(&self) -> Option<PendingOperatorRotation> {
        self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "get_pending_operator_rotation"),
            Self::empty_args(self.0),
        )
    }

    pub fn get_operator(&self) -> Address {
        self.0.invoke_contract(
            self.1,
            &Symbol::new(self.0, "get_operator"),
            Self::empty_args(self.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Env, IntoVal};

    fn setup() -> (Env, PauseManagerClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);
        (env, client)
    }

    #[test]
    fn test_initialize_sets_operator_and_unpaused() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        assert!(!client.is_paused());
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_initialize_cannot_be_called_twice() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);
        client.initialize(&operator);
    }

    #[test]
    fn test_pause_sets_paused_state() {
        let (_env, client) = setup();
        client.pause();
        assert!(client.is_paused());
    }

    #[test]
    fn test_unpause_resumes_state() {
        let (_env, client) = setup();
        client.pause();
        assert!(client.is_paused());
        client.unpause();
        assert!(!client.is_paused());
    }

    #[test]
    fn test_can_pause_multiple_times() {
        let (_env, client) = setup();
        client.pause();
        assert!(client.is_paused());
        client.pause();
        assert!(client.is_paused());
    }

    // ── Issue #192: two-step operator rotation ───────────────────────────────

    #[test]
    fn test_propose_operator_rotation_creates_pending() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        let new_operator = Address::generate(&env);
        client.propose_operator_rotation(&operator, &new_operator);

        let proposal = client.get_pending_operator_rotation().unwrap();
        assert_eq!(proposal.new_operator, new_operator);
        assert_eq!(proposal.proposed_by, operator);
    }

    #[test]
    fn test_accept_operator_rotation_completes_transfer() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        let new_operator = Address::generate(&env);
        client.propose_operator_rotation(&operator, &new_operator);
        client.accept_operator_rotation(&new_operator);

        // New operator can pause
        client.pause();
        assert!(client.is_paused());
    }

    #[test]
    fn test_cancel_operator_rotation_removes_pending() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        let new_operator = Address::generate(&env);
        client.propose_operator_rotation(&operator, &new_operator);
        client.cancel_operator_rotation(&operator);

        // Old operator can still pause
        client.pause();
        assert!(client.is_paused());
    }

    #[test]
    #[should_panic(expected = "A pending operator rotation already exists")]
    fn test_duplicate_operator_rotation_proposal_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        let new_op1 = Address::generate(&env);
        let new_op2 = Address::generate(&env);
        client.propose_operator_rotation(&operator, &new_op1);
        client.propose_operator_rotation(&operator, &new_op2);
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_cancel_operator_rotation_rejects_non_operator() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        let new_operator = Address::generate(&env);
        let attacker = Address::generate(&env);
        client.propose_operator_rotation(&operator, &new_operator);
        client.cancel_operator_rotation(&attacker);
    }

    #[test]
    #[should_panic(expected = "No pending operator rotation to cancel")]
    fn test_cancel_operator_rotation_without_proposal_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        client.cancel_operator_rotation(&operator);
    }

    #[test]
    #[should_panic(expected = "No pending operator rotation")]
    fn test_accept_operator_rotation_without_proposal_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        let new_operator = Address::generate(&env);
        client.accept_operator_rotation(&new_operator);
    }

    // ── Issue #275: operator rotation revokes old operator access ────────────
    //
    // The two-step rotation tests above (issue #192) confirm the *new*
    // operator gains access and that a *cancelled* rotation leaves the old
    // operator in place. They don't confirm the flip side required for real
    // team rotation: once a rotation is *accepted*, the *old* operator's
    // privileges must be gone, not merely superseded. These tests exercise
    // that revocation directly, and confirm the new operator inherits full
    // admin control (able to start the next rotation in turn).

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_old_operator_cannot_pause_after_rotation_completed() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let old_operator = Address::generate(&env);
        let new_operator = Address::generate(&env);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &old_operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (old_operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&old_operator);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &old_operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "propose_operator_rotation",
                args: (old_operator.clone(), new_operator.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.propose_operator_rotation(&old_operator, &new_operator);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &new_operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "accept_operator_rotation",
                args: (new_operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.accept_operator_rotation(&new_operator);

        // The rotation is complete. The old operator's signature is no
        // longer sufficient authorization for `pause` — the contract now
        // requires the new operator's signature.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &old_operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "pause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.pause();
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_old_operator_cannot_unpause_after_rotation_completed() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let old_operator = Address::generate(&env);
        let new_operator = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&old_operator);
        client.propose_operator_rotation(&old_operator, &new_operator);
        client.accept_operator_rotation(&new_operator);
        // New operator pauses first, so unpause is the meaningful action to
        // deny the old operator.
        client.pause();

        // Revert to explicit, single-signer auth for the negative check.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &old_operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "unpause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.unpause();
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the current operator")]
    fn test_old_operator_cannot_propose_new_rotation_after_being_replaced() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let old_operator = Address::generate(&env);
        let new_operator = Address::generate(&env);
        client.initialize(&old_operator);
        client.propose_operator_rotation(&old_operator, &new_operator);
        client.accept_operator_rotation(&new_operator);

        // The old operator attempts to act as if it were still current —
        // must be rejected even though it was the operator moments ago.
        let another_operator = Address::generate(&env);
        client.propose_operator_rotation(&old_operator, &another_operator);
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_old_operator_cannot_cancel_after_rotation_completed() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let old_operator = Address::generate(&env);
        let new_operator = Address::generate(&env);
        client.initialize(&old_operator);
        client.propose_operator_rotation(&old_operator, &new_operator);
        client.accept_operator_rotation(&new_operator);

        client.cancel_operator_rotation(&old_operator);
    }

    #[test]
    fn test_new_operator_retains_full_control_and_can_start_next_rotation() {
        // Admin control must be preserved across rotation: the incoming
        // operator gets the exact same capabilities the outgoing one had,
        // including the ability to pause/unpause and to propose the next
        // rotation in turn.
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let op_1 = Address::generate(&env);
        let op_2 = Address::generate(&env);
        let op_3 = Address::generate(&env);

        client.initialize(&op_1);
        client.propose_operator_rotation(&op_1, &op_2);
        client.accept_operator_rotation(&op_2);

        client.pause();
        assert!(client.is_paused());
        client.unpause();
        assert!(!client.is_paused());

        client.propose_operator_rotation(&op_2, &op_3);
        let proposal = client.get_pending_operator_rotation().unwrap();
        assert_eq!(proposal.new_operator, op_3);
        assert_eq!(proposal.proposed_by, op_2);
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_unauthorized_pause_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let operator = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&operator);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "pause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.pause();
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_unauthorized_unpause_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let operator = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&operator);

        // Pause as operator
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "pause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.pause();

        // Try to unpause as attacker
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "unpause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.unpause();
    }

    #[test]
    fn test_is_paused_returns_false_when_not_initialized() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        assert!(!client.is_paused());
    }

    #[test]
    #[should_panic(expected = "Not initialized")]
    fn test_pause_panics_when_not_initialized() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        client.pause();
    }
}
