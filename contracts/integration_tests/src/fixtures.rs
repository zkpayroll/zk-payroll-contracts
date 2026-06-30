/// Reusable fixture data for local testing and development.
///
/// Provides deterministic test data (companies, employees, payroll periods) ensuring
/// consistency across contract, SDK, and dashboard development.
///
/// All fixtures are deterministic and documented in `docs/fixtures-guide.md`.
#[cfg(test)]
pub mod fixtures {
    use soroban_sdk::{Address, BytesN, Env};

    // ── Company Fixtures ─────────────────────────────────────────────────────

    pub struct CompanyFixture {
        pub id: u64,
        pub name: &'static str,
    }

    pub const ACME_CORP: CompanyFixture = CompanyFixture {
        id: 0,
        name: "Acme Corp",
    };

    pub const TECHSTART_INC: CompanyFixture = CompanyFixture {
        id: 1,
        name: "TechStart Inc",
    };

    pub const GLOBALPAY_LTD: CompanyFixture = CompanyFixture {
        id: 2,
        name: "GlobalPay Ltd",
    };

    // ── Employee Fixtures ────────────────────────────────────────────────────

    pub struct EmployeeFixture {
        pub id: u8,
        pub name: &'static str,
        pub salary: u64,
        pub blinding_factor: u8,
    }

    pub const ALICE: EmployeeFixture = EmployeeFixture {
        id: 0,
        name: "Alice",
        salary: 5000,
        blinding_factor: 123,
    };

    pub const BOB: EmployeeFixture = EmployeeFixture {
        id: 1,
        name: "Bob",
        salary: 3500,
        blinding_factor: 456,
    };

    pub const CAROL: EmployeeFixture = EmployeeFixture {
        id: 2,
        name: "Carol",
        salary: 7200,
        blinding_factor: 789,
    };

    pub const DAVID: EmployeeFixture = EmployeeFixture {
        id: 3,
        name: "David",
        salary: 4500,
        blinding_factor: 111,
    };

    pub const EMMA: EmployeeFixture = EmployeeFixture {
        id: 4,
        name: "Emma",
        salary: 6000,
        blinding_factor: 222,
    };

    pub const FRANK: EmployeeFixture = EmployeeFixture {
        id: 5,
        name: "Frank",
        salary: 5500,
        blinding_factor: 333,
    };

    // ── Address Derivation ───────────────────────────────────────────────────

    /// Generate a deterministic Address from a seed byte.
    ///
    /// This creates a stable, reproducible address for fixtures.
    /// Not secure for production — fixtures only.
    pub fn address_from_seed(env: &Env, seed: u8) -> Address {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Address::from_contract_id(&BytesN::from_array(env, &bytes))
    }

    /// Generate a deterministic 32-byte blinding factor.
    pub fn blinding_bytes(factor: u8) -> BytesN<32> {
        let mut bytes = [0u8; 32];
        bytes[31] = factor;
        // BytesN::from_array requires an &Env, so callers must construct this
        // Cannot be done in const context without env
        bytes
    }

    // ── Payroll Period Fixtures ──────────────────────────────────────────────

    pub struct PayrollPeriodFixture {
        pub label: &'static str,
        pub company_id: u64,
        pub start_date: &'static str, // YYYY-MM-DD
        pub end_date: &'static str,
        pub is_active: bool,
    }

    pub const Q1_2024_ACME: PayrollPeriodFixture = PayrollPeriodFixture {
        label: "Q1 2024",
        company_id: 0,
        start_date: "2024-01-01",
        end_date: "2024-03-31",
        is_active: false,
    };

    pub const Q2_2024_ACME: PayrollPeriodFixture = PayrollPeriodFixture {
        label: "Q2 2024",
        company_id: 0,
        start_date: "2024-04-01",
        end_date: "2024-06-30",
        is_active: true,
    };

    pub const FEB_2024_GLOBALPAY: PayrollPeriodFixture = PayrollPeriodFixture {
        label: "Feb 2024",
        company_id: 2,
        start_date: "2024-02-01",
        end_date: "2024-02-29",
        is_active: false,
    };

    // ── Test Assertions ──────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_company_fixtures_load() {
            assert_eq!(ACME_CORP.id, 0);
            assert_eq!(ACME_CORP.name, "Acme Corp");

            assert_eq!(TECHSTART_INC.id, 1);
            assert_eq!(GLOBALPAY_LTD.id, 2);
        }

        #[test]
        fn test_employee_fixtures_load() {
            assert_eq!(ALICE.salary, 5000);
            assert_eq!(ALICE.name, "Alice");
            assert_eq!(ALICE.blinding_factor, 123);

            assert_eq!(BOB.salary, 3500);
            assert_eq!(CAROL.salary, 7200);
        }

        #[test]
        fn test_payroll_period_fixtures() {
            assert_eq!(Q1_2024_ACME.company_id, 0);
            assert_eq!(Q1_2024_ACME.is_active, false);

            assert_eq!(Q2_2024_ACME.is_active, true);
            assert_eq!(FEB_2024_GLOBALPAY.company_id, 2);
        }

        #[test]
        fn test_address_from_seed_deterministic() {
            let env = soroban_sdk::Env::default();

            let addr1 = address_from_seed(&env, 1);
            let addr2 = address_from_seed(&env, 1);

            // Same seed produces same address
            assert_eq!(addr1, addr2);
        }

        #[test]
        fn test_address_from_seed_unique() {
            let env = soroban_sdk::Env::default();

            let addr1 = address_from_seed(&env, 1);
            let addr2 = address_from_seed(&env, 2);

            // Different seeds produce different addresses
            assert_ne!(addr1, addr2);
        }

        #[test]
        fn test_blinding_bytes() {
            let bytes_123 = blinding_bytes(123);
            assert_eq!(bytes_123[31], 123);
            assert_eq!(bytes_123[0], 0);

            let bytes_255 = blinding_bytes(255);
            assert_eq!(bytes_255[31], 255);
        }
    }
}
