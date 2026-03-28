//! `reconcile` command — cross-reference on-chain `PayrollProcessed` events
//! with the local SQLite blinding-factor database.
//!
//! For every payment event the command:
//! 1. Looks up the employee public key in the local database.
//! 2. Reconstructs a human-readable narrative from the stored salary.
//! 3. Renders everything as a table to stdout.
//!
//! # Example output
//!
//! ```text
//! Reconciliation report for company: ACME_CORP
//! Soroban RPC : https://soroban-testnet.stellar.org
//! Contract    : CXXX...
//! Ledgers     : 1000000 →
//!
//! ┌────────────────────────────────────────────────┬──────────────┬────────┬──────────────────────┬──────────────┐
//! │ Employee                                       │ Amount (XLM) │ Period │ Ledger closed at     │ In local DB? │
//! ├────────────────────────────────────────────────┼──────────────┼────────┼──────────────────────┼──────────────┤
//! │ GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER… │       50.000 │      1 │ 2024-12-01T00:00:00Z │ ✓            │
//! └────────────────────────────────────────────────┴──────────────┴────────┴──────────────────────┴──────────────┘
//! ```

use anyhow::{Context, Result};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Table};

use crate::{db, rpc};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default Soroban RPC endpoint (Stellar testnet).
pub const DEFAULT_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// 1 XLM = 10 000 000 stroops.
const STROOPS_PER_XLM: i128 = 10_000_000;

// ── Public entry point ────────────────────────────────────────────────────────

/// Arguments for the `reconcile` command.
pub struct ReconcileArgs<'a> {
    pub rpc_url: &'a str,
    pub contract_id: &'a str,
    pub company_id: &'a str,
    pub start_ledger: u32,
}

/// Run the reconcile command: fetch events, cross-reference DB, print table.
pub fn run(args: ReconcileArgs<'_>) -> Result<()> {
    // ── Print header ──────────────────────────────────────────────────────────
    println!("Reconciliation report for company: {}", args.company_id);
    println!("Soroban RPC  : {}", args.rpc_url);
    println!("Contract     : {}", args.contract_id);
    println!("Start ledger : {}", args.start_ledger);
    println!();

    // ── Fetch on-chain events ─────────────────────────────────────────────────
    let events = rpc::fetch_payroll_events(
        args.rpc_url,
        args.contract_id,
        args.company_id,
        args.start_ledger,
    )
    .context("Failed to fetch PayrollProcessed events from Soroban RPC")?;

    if events.is_empty() {
        println!(
            "No PayrollProcessed events found for company '{}' from ledger {}.",
            args.company_id, args.start_ledger
        );
        return Ok(());
    }

    // ── Open local database ───────────────────────────────────────────────────
    let db_path = db::db_path()?;
    let conn_opt = if db_path.exists() {
        Some(db::open(&db_path).context("Failed to open local database")?)
    } else {
        None
    };

    // ── Build table ───────────────────────────────────────────────────────────
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            "Employee",
            "Amount (XLM)",
            "Period",
            "Ledger closed at",
            "In local DB?",
            "Narrative",
        ]);

    for ev in &events {
        let in_db = match &conn_opt {
            Some(conn) => db::get_employee(conn, &ev.employee)?.is_some(),
            None => false,
        };

        let in_db_mark = if in_db { "✓" } else { "✗" };

        let narrative = build_narrative(&ev.employee, ev.amount, ev.period, &ev.ledger_closed_at);

        table.add_row(vec![
            Cell::new(truncate(&ev.employee, 20)),
            Cell::new(stroops_to_xlm_display(ev.amount)),
            Cell::new(ev.period.to_string()),
            Cell::new(&ev.ledger_closed_at),
            Cell::new(in_db_mark),
            Cell::new(narrative),
        ]);

        // Warn about unrecognised employees.
        if !in_db {
            eprintln!(
                "WARN: Employee {} appears in on-chain events but is not in the local database.",
                ev.employee
            );
        }
    }

    println!("{table}");
    println!("{} payment(s) found.", events.len());

    // ── Salary cross-check ────────────────────────────────────────────────────
    if let Some(conn) = &conn_opt {
        let mismatches = check_salary_mismatches(conn, &events)?;
        if mismatches > 0 {
            eprintln!(
                "WARN: {} payment(s) have amounts that differ from the local salary record.",
                mismatches
            );
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a human-readable payment narrative.
///
/// E.g. "On 2024-12-01, paid GAAZ… 50.000 XLM (period 1)"
fn build_narrative(employee: &str, amount: i128, period: u32, closed_at: &str) -> String {
    let date = closed_at.split('T').next().unwrap_or(closed_at);
    format!(
        "On {}, paid {}… {} (period {})",
        date,
        &employee[..8.min(employee.len())],
        stroops_to_xlm_display(amount),
        period,
    )
}

/// Format a stroop amount as "123.456 XLM".
fn stroops_to_xlm_display(stroops: i128) -> String {
    let xlm = stroops as f64 / STROOPS_PER_XLM as f64;
    format!("{xlm:.3} XLM")
}

/// Truncate a string and append "…" if longer than `max` characters.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Count payments where the on-chain amount differs from the local salary.
fn check_salary_mismatches(
    conn: &rusqlite::Connection,
    events: &[rpc::PayrollEvent],
) -> Result<usize> {
    let mut count = 0usize;
    for ev in events {
        if let Some((_blinding, salary)) = db::get_employee(conn, &ev.employee)? {
            if salary as i128 != ev.amount {
                eprintln!(
                    "WARN: Amount mismatch for {}: on-chain={} stroops, local DB={} stroops",
                    ev.employee, ev.amount, salary
                );
                count += 1;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("GABC", 20), "GABC");
    }

    #[test]
    fn truncate_long_string_appends_ellipsis() {
        let s = "G".repeat(30);
        let result = truncate(&s, 20);
        assert!(result.ends_with('…'));
        // '…' is 1 Unicode scalar + 20 ASCII chars = 21 characters total.
        assert!(result.chars().count() <= 21);
    }

    #[test]
    fn stroops_to_xlm_display_formats_correctly() {
        assert_eq!(stroops_to_xlm_display(10_000_000), "1.000 XLM");
        assert_eq!(stroops_to_xlm_display(50_000_000), "5.000 XLM");
        assert_eq!(stroops_to_xlm_display(123_456_789), "12.346 XLM");
    }

    #[test]
    fn narrative_includes_date_and_period() {
        let n = build_narrative("GAAZ1234", 10_000_000, 3, "2024-12-01T00:00:00Z");
        assert!(n.contains("2024-12-01"));
        assert!(n.contains("period 3"));
        assert!(n.contains("1.000 XLM"));
    }
}
