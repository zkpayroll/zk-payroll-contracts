//! ZK Payroll CLI — off-chain commitment generation for privacy-preserving
//! payroll on Stellar/Soroban.
//!
//! # Commands
//!
//! | Command | Purpose |
//! |---------|---------|
//! | `init-company` | Create the local SQLite database at `~/.zk-payroll/company_db.sqlite` |
//! | `add-employee <pubkey> <amount>` | Generate a BN254 blinding factor, compute `Poseidon(salary, blinding)`, persist both, and print the commitment |
//!
//! # Security model
//!
//! The `~/.zk-payroll/` directory holds the **only** copies of employee blinding
//! factors.  Without a blinding factor it is impossible to reconstruct the salary
//! commitment required by the ZK circuit, permanently blocking payment execution
//! for the affected employee.
//!
//! **Back up `~/.zk-payroll/` to an encrypted, offline location immediately.**

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

mod crypto;
mod db;

// ── Warning banner ────────────────────────────────────────────────────────────

const BACKUP_WARNING: &str = "\
+------------------------------------------------------------------+
|                *** CRITICAL BACKUP WARNING ***                   |
|                                                                  |
|  Your ~/.zk-payroll folder contains blinding factors that are   |
|  REQUIRED to generate future ZK payment proofs.                 |
|                                                                  |
|  If these are lost, employee payments through the smart          |
|  contract will be PERMANENTLY BLOCKED — there is NO recovery.   |
|                                                                  |
|  Action required: back up ~/.zk-payroll to an encrypted,        |
|  offline location (hardware wallet, encrypted USB, etc.) NOW.   |
+------------------------------------------------------------------+";

// ── CLI definition ────────────────────────────────────────────────────────────

/// ZK Payroll CLI — off-chain proof-preparation tool for privacy-preserving
/// payroll on Stellar/Soroban.
///
/// This tool runs entirely on your local machine.  No salary data or blinding
/// factors are ever transmitted over the network.
#[derive(Parser)]
#[command(name = "zk-payroll")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialise the local ZK Payroll database.
    ///
    /// Creates ~/.zk-payroll/company_db.sqlite with the blinding_factors
    /// table.  Safe to run multiple times (idempotent).
    InitCompany,

    /// Register an employee and generate their salary commitment.
    ///
    /// Generates a cryptographically secure random 254-bit BN254 scalar
    /// (the blinding factor), computes Poseidon(salary, blinding_factor),
    /// persists both to the local database, and prints the commitment.
    ///
    /// SECURITY: The generated blinding factor is stored ONLY in the local
    /// database.  Back up ~/.zk-payroll immediately after running this command.
    AddEmployee {
        /// Employee Stellar public key (56-character G... address).
        pubkey: String,

        /// Gross salary amount in stroops (1 XLM = 10,000,000 stroops).
        amount: u64,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::InitCompany => cmd_init_company(),
        Commands::AddEmployee { pubkey, amount } => cmd_add_employee(&pubkey, amount),
    }
}

// ── Command implementations ───────────────────────────────────────────────────

/// `init-company` — create ~/.zk-payroll/company_db.sqlite.
fn cmd_init_company() -> Result<()> {
    let db_path = db::db_path()?;

    let dir = db_path
        .parent()
        .context("Cannot determine the parent directory for the database file")?;

    // Create ~/.zk-payroll/ with restrictive permissions (owner-only on Unix).
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Cannot create directory '{}'", dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Cannot set permissions on '{}'", dir.display()))?;
    }

    // Open (or re-open) the database and apply the schema.
    let conn = db::open(&db_path)?;
    db::initialise(&conn)?;

    // Restrict the database file itself to owner read/write on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Cannot set permissions on '{}'", db_path.display()))?;
    }

    println!("ZK Payroll database initialised at: {}", db_path.display());
    println!();
    println!("{}", BACKUP_WARNING);

    Ok(())
}

/// `add-employee <pubkey> <amount>` — generate blinding factor, compute
/// commitment, persist, and print.
fn cmd_add_employee(pubkey: &str, amount: u64) -> Result<()> {
    // ── Input validation ──────────────────────────────────────────────────────

    validate_stellar_pubkey(pubkey)?;

    // ── Database sanity check ─────────────────────────────────────────────────

    let db_path = db::db_path()?;
    if !db_path.exists() {
        bail!(
            "Database not found at '{}'.\n\
             Run `zk-payroll init-company` to create it first.",
            db_path.display()
        );
    }

    let conn = db::open(&db_path)?;

    if db::employee_exists(&conn, pubkey)? {
        bail!(
            "Employee '{}' already exists in the database.\n\
             Each employee can have only one active commitment at a time.\n\
             To update their salary, use `zk-payroll update-salary {} <new-amount>`.",
            pubkey,
            pubkey
        );
    }

    // ── Cryptographic operations ──────────────────────────────────────────────

    // 1. Generate a fresh BN254 scalar blinding factor using OsRng.
    let blinding_bytes = crypto::gen_blinding_factor();
    let blinding_hex = hex::encode(blinding_bytes);

    // 2. Compute Poseidon(salary, blinding_factor) — the on-chain commitment.
    let commitment_bytes = crypto::poseidon_commitment(amount, &blinding_bytes)
        .context("Failed to compute Poseidon commitment")?;
    let commitment_hex = hex::encode(commitment_bytes);

    // ── Persist to database ───────────────────────────────────────────────────

    db::insert_employee(&conn, pubkey, &blinding_hex, amount)
        .context("Failed to persist employee record")?;

    // ── Output ────────────────────────────────────────────────────────────────

    println!("Successfully generated commitment: 0x{}", commitment_hex);
    println!();
    println!("  Employee : {}", pubkey);
    println!("  Salary   : {} stroops", amount);
    println!();
    println!("{}", BACKUP_WARNING);

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Validate that `pubkey` looks like a Stellar public key.
///
/// Stellar public keys (G... addresses / StrKeys) are exactly 56 characters
/// long, start with 'G', and contain only uppercase alphanumeric characters
/// from the Stellar StrKey alphabet.
///
/// This is a lightweight sanity check — full StrKey checksum validation would
/// require an additional dependency.
fn validate_stellar_pubkey(pubkey: &str) -> Result<()> {
    // Stellar StrKey public keys start with 'G' and are always 56 characters.
    if pubkey.len() != 56 || !pubkey.starts_with('G') {
        bail!(
            "Invalid Stellar public key: '{}'\n\
             Expected a 56-character address starting with 'G' \
             (e.g. GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN).",
            pubkey
        );
    }

    // StrKey uses base32 alphabet: A-Z 2-7.
    let valid_chars = pubkey
        .chars()
        .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c));

    if !valid_chars {
        bail!(
            "Invalid Stellar public key: '{}'\n\
             StrKey addresses may only contain uppercase letters A-Z and digits 2-7.",
            pubkey
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a syntactically valid 56-char Stellar G-address for use in tests.
    // Stellar StrKey public keys: prefix 'G' + 55 chars from [A-Z2-7].
    fn valid_key() -> String {
        format!("G{}", "A".repeat(55))
    }

    #[test]
    fn valid_pubkey_passes_validation() {
        assert!(validate_stellar_pubkey(&valid_key()).is_ok());
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        // Same length as a real key but starts with 'S' (Stellar secret key prefix).
        let bad = format!("S{}", "A".repeat(55));
        assert!(
            validate_stellar_pubkey(&bad).is_err(),
            "S-prefix must be rejected"
        );
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(
            validate_stellar_pubkey("GABC").is_err(),
            "short key must be rejected"
        );
        assert!(
            validate_stellar_pubkey(&format!("G{}", "A".repeat(60))).is_err(),
            "long key (61 chars) must be rejected"
        );
    }

    #[test]
    fn invalid_chars_are_rejected() {
        // Replace a character deep in the key with '!' (not in StrKey alphabet).
        let base = valid_key();
        let mut chars: Vec<char> = base.chars().collect();
        chars[20] = '!';
        let bad_key: String = chars.into_iter().collect();
        assert!(
            validate_stellar_pubkey(&bad_key).is_err(),
            "invalid char must be rejected"
        );
    }
}
