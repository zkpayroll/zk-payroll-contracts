//! SQLite persistence layer for the ZK Payroll CLI.
//!
//! All employee blinding factors and salary amounts are stored locally at
//! `~/.zk-payroll/company_db.sqlite`.  This file MUST be kept confidential
//! and backed up — loss of blinding factors permanently prevents future proof
//! generation for the affected employees.
//!
//! # Schema
//! ```sql
//! CREATE TABLE blinding_factors (
//!     employee_pubkey      TEXT    PRIMARY KEY,
//!     blinding_factor      TEXT    NOT NULL,
//!     current_salary_amount INTEGER NOT NULL
//! );
//! ```
//!
//! The `blinding_factor` column holds a 64-character lowercase hex string
//! encoding the 32-byte little-endian BN254 scalar produced by
//! [`crate::crypto::gen_blinding_factor`].

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

// ── Path resolution ───────────────────────────────────────────────────────────

/// Returns the canonical path `~/.zk-payroll/company_db.sqlite`.
///
/// # Errors
/// Returns an error when the home directory cannot be determined (e.g. on a
/// system where `$HOME` / `USERPROFILE` is unset).
pub fn db_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context(
        "Cannot determine the home directory. \
         Ensure the HOME (Unix) or USERPROFILE (Windows) environment variable is set.",
    )?;
    Ok(home.join(".zk-payroll").join("company_db.sqlite"))
}

// ── Connection management ─────────────────────────────────────────────────────

/// Open (or create) the SQLite database at `path`.
///
/// WAL mode is enabled for better concurrent-read performance and crash safety.
pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("Cannot open SQLite database at {}", path.display()))?;

    // Enable WAL journal mode for crash safety.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .context("Failed to configure SQLite pragmas")?;

    Ok(conn)
}

// ── Schema initialisation ─────────────────────────────────────────────────────

/// Create the `blinding_factors` table if it does not already exist.
///
/// Safe to call on an already-initialised database (idempotent via
/// `CREATE TABLE IF NOT EXISTS`).
pub fn initialise(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS blinding_factors (
            employee_pubkey       TEXT     PRIMARY KEY,
            blinding_factor       TEXT     NOT NULL,
            current_salary_amount INTEGER  NOT NULL
        );",
    )
    .context("Failed to create blinding_factors table")?;
    Ok(())
}

// ── Write operations ─────────────────────────────────────────────────────────

/// Insert a new employee record.
///
/// # Arguments
/// * `pubkey` — Stellar public key (G... address), used as the primary key.
/// * `blinding_hex` — 64-character lowercase hex of the 32-byte LE blinding scalar.
/// * `salary` — gross salary amount in stroops.
///
/// # Errors
/// Returns an error if a record for `pubkey` already exists.  Use
/// [`update_employee_salary`] to change an existing employee's salary.
pub fn insert_employee(
    conn: &Connection,
    pubkey: &str,
    blinding_hex: &str,
    salary: u64,
) -> Result<()> {
    let rows = conn
        .execute(
            "INSERT INTO blinding_factors \
             (employee_pubkey, blinding_factor, current_salary_amount) \
             VALUES (?1, ?2, ?3)",
            params![pubkey, blinding_hex, salary as i64],
        )
        .with_context(|| {
            format!(
                "Failed to insert employee '{}'. \
                 The public key may already exist — use update-salary to change their salary.",
                pubkey
            )
        })?;

    debug_assert_eq!(rows, 1, "INSERT must affect exactly one row");
    Ok(())
}

/// Return the stored blinding factor and salary for `pubkey`, if present.
///
/// Returns `Ok(None)` when the employee is not in the database.
pub fn get_employee(conn: &Connection, pubkey: &str) -> Result<Option<(String, u64)>> {
    let result = conn.query_row(
        "SELECT blinding_factor, current_salary_amount \
         FROM blinding_factors WHERE employee_pubkey = ?1",
        params![pubkey],
        |row| {
            let blinding: String = row.get(0)?;
            let salary_i64: i64 = row.get(1)?;
            Ok((blinding, salary_i64 as u64))
        },
    );

    match result {
        Ok(pair) => Ok(Some(pair)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Database query failed for pubkey '{}'", pubkey)),
    }
}

/// Returns `true` if `pubkey` already has a record in the database.
pub fn employee_exists(conn: &Connection, pubkey: &str) -> Result<bool> {
    Ok(get_employee(conn, pubkey)?.is_some())
}

/// Update the salary amount for an existing employee.
///
/// Does **not** regenerate the blinding factor — only the salary figure changes.
/// Call this when an employee receives a raise; generate a new commitment
/// after updating.
///
/// # Errors
/// Returns an error if the employee does not exist.
pub fn update_employee_salary(conn: &Connection, pubkey: &str, new_salary: u64) -> Result<()> {
    if !employee_exists(conn, pubkey)? {
        bail!(
            "Employee '{}' not found in the database. \
             Run `zk-payroll add-employee` first.",
            pubkey
        );
    }

    let rows = conn
        .execute(
            "UPDATE blinding_factors SET current_salary_amount = ?1 \
             WHERE employee_pubkey = ?2",
            params![new_salary as i64, pubkey],
        )
        .context("Failed to update employee salary")?;

    debug_assert_eq!(rows, 1, "UPDATE must affect exactly one row");
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .unwrap();
        initialise(&conn).unwrap();
        conn
    }

    #[test]
    fn initialise_is_idempotent() {
        let conn = in_memory_conn();
        // Second call must not error.
        initialise(&conn).unwrap();
    }

    #[test]
    fn insert_and_retrieve_employee() {
        let conn = in_memory_conn();
        let pubkey = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
        let blinding = "a".repeat(64);

        insert_employee(&conn, pubkey, &blinding, 5_000_000).unwrap();

        let (stored_blinding, stored_salary) = get_employee(&conn, pubkey).unwrap().unwrap();
        assert_eq!(stored_blinding, blinding);
        assert_eq!(stored_salary, 5_000_000);
    }

    #[test]
    fn insert_duplicate_pubkey_errors() {
        let conn = in_memory_conn();
        let pubkey = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
        let blinding = "b".repeat(64);

        insert_employee(&conn, pubkey, &blinding, 1_000).unwrap();
        let result = insert_employee(&conn, pubkey, &blinding, 2_000);
        assert!(result.is_err(), "duplicate insert must fail");
    }

    #[test]
    fn get_employee_returns_none_for_unknown_pubkey() {
        let conn = in_memory_conn();
        let result = get_employee(&conn, "GNOBODY").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn update_salary_changes_stored_value() {
        let conn = in_memory_conn();
        let pubkey = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
        let blinding = "c".repeat(64);

        insert_employee(&conn, pubkey, &blinding, 5_000_000).unwrap();
        update_employee_salary(&conn, pubkey, 6_000_000).unwrap();

        let (_, salary) = get_employee(&conn, pubkey).unwrap().unwrap();
        assert_eq!(salary, 6_000_000);
    }

    #[test]
    fn update_salary_errors_for_unknown_employee() {
        let conn = in_memory_conn();
        let result = update_employee_salary(&conn, "GNOBODY", 1_000);
        assert!(result.is_err(), "update on non-existent employee must fail");
    }

    #[test]
    fn employee_exists_reflects_insertion() {
        let conn = in_memory_conn();
        let pubkey = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

        assert!(!employee_exists(&conn, pubkey).unwrap());
        insert_employee(&conn, pubkey, &"d".repeat(64), 1).unwrap();
        assert!(employee_exists(&conn, pubkey).unwrap());
    }
}
