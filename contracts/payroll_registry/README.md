# payroll_registry Architecture Interface

This document defines the canonical interface and storage model for the
`payroll_registry` contract.

## Entrypoints

| Method | Parameters | Returns | Access Control |
| --- | --- | --- | --- |
| `register_company` | `admin: Address`, `treasury: Address` | `u64` | None |
| `add_employee` | `company_id: u64`, `employee: Address`, `commitment: BytesN<32>` | `()` | `require_auth(admin)` |
| `remove_employee` | `company_id: u64`, `employee: Address` | `()` | `require_auth(admin)` |
| `update_commitment` | `company_id: u64`, `employee: Address`, `new_commitment: BytesN<32>` | `()` | `require_auth(admin)` |

## Rust Interface Definitions

The contract interface is defined by the Rust trait:

- `PayrollRegistryTrait`
  - `fn register_company(env: Env, admin: Address, treasury: Address) -> u64`
  - `fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>)`
  - `fn remove_employee(env: Env, company_id: u64, employee: Address)`
  - `fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>)`

## Storage Types and Keys

Storage is implemented using `DataKey`:

- `DataKey::Company(u64)` maps to `CompanyInfo { admin: Address, treasury: Address }`
- `DataKey::Employee(u64, Address)` maps to `BytesN<32>` (active Poseidon commitment)

The `CompanyInfo` struct definition in Rust:

- `pub struct CompanyInfo { pub admin: Address, pub treasury: Address }`

## Notes

- Company IDs are allocated sequentially and persisted with `DataKey::NextCompanyId`.
- Admin-gated methods load `CompanyInfo` via `DataKey::Company(company_id)` and call
  `info.admin.require_auth()` before mutating employee state.
