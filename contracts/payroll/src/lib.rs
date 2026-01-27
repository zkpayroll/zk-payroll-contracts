#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

#[contract]
pub struct Payroll;

#[contractimpl]
impl Payroll {
    pub fn initialize(_e: Env, _admin: Address, _token: Address) {
        // Init
    }

    pub fn deposit(_e: Env, _from: Address, _amount: i128) {
        // Deposit
    }

    pub fn process_payroll(_e: Env, _recipients: Vec<Address>, _amounts: Vec<i128>) {
        // Process
    }
}
