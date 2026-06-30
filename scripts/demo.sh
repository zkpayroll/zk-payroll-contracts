#!/usr/bin/env bash

# demo.sh - End‑to‑end demo of zk‑payroll‑contracts on Soroban testnet
# This script is intended for contributors to quickly see the full lifecycle:
#   * Prerequisite checks
#   * Key generation and funding
#   * Contract compilation & deployment
#   * Company registration
#   * Employee onboarding with ZK commitment
#   * Treasury funding
#   * Payment proof generation
#   * Private payment execution
#   * Verification
# It aborts on any error and prints actionable messages.

set -euo pipefail

# Utility to print errors and exit
error() {
  echo "[ERROR] $*" >&2
  exit 1
}

# ------------------------------------------------------------
# 1. Prerequisite checks
# ------------------------------------------------------------
required_bins=(cargo stellar soroban node npm circom snarkjs jq)
for bin in "${required_bins[@]}"; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    error "Required binary '$bin' not found in PATH. Please install it before running the demo."
  fi
done

echo "All required binaries are present."

# ------------------------------------------------------------
# 2. Setup: generate keypairs for admin, employee, treasury
# ------------------------------------------------------------
generate_keypair() {
  local name="$1"
  echo "Generating keypair for $name..."
  local key_output
  key_output=$(stellar keys generate 2>/dev/null) || error "Failed to generate keypair for $name"
  local secret=$(echo "$key_output" | grep -i secret | awk '{print $2}')
  local public=$(echo "$key_output" | grep -i public | awk '{print $2}')
  export ${name}_SECRET="$secret"
  export ${name}_PUBLIC="$public"
}

generate_keypair ADMIN
generate_keypair EMPLOYEE
generate_keypair TREASURY

# ------------------------------------------------------------
# 3. Fund admin and treasury via friend‑bot (testnet only)
# ------------------------------------------------------------
friendbot_fund() {
  local address="$1"
  echo "Funding $address via friend‑bot..."
  stellar friendbot "$address" >/dev/null 2>&1 || error "Friend‑bot funding failed for $address"
}

friendbot_fund "$ADMIN_PUBLIC"
friendbot_fund "$TREASURY_PUBLIC"

echo "Admin and Treasury funded."

# ------------------------------------------------------------
# 4. Compile contracts (using stellar cli)
# ------------------------------------------------------------
echo "Compiling contracts..."
stellar contract build >/dev/null 2>&1 || error "Contract compilation failed"

echo "Contracts compiled successfully."

# ------------------------------------------------------------
# 5. Deploy contracts to testnet
# ------------------------------------------------------------
# Helper to deploy a contract and capture its ID
deploy_contract() {
  local wasm_path="$1"
  local source="$2"
  echo "Deploying $(basename "$wasm_path")..."
  local deploy_output
  deploy_output=$(stellar contract deploy \
    --wasm "$wasm_path" \
    --network testnet \
    --source "$source" 2>&1) || error "Deployment failed for $wasm_path"
  local contract_id=$(echo "$deploy_output" | grep -i "contract id" | awk '{print $NF}')
  if [[ -z "$contract_id" ]]; then
    error "Could not parse contract ID from deployment output"
  fi
  echo "$contract_id"
}

# Paths to compiled WASM files (relative to repo root)
REGISTRY_WASM="target/wasm32-unknown-unknown/release/payroll_registry.wasm"
PAYMENT_WASM="target/wasm32-unknown-unknown/release/payment_executor.wasm"

REGISTRY_ID=$(deploy_contract "$REGISTRY_WASM" "$ADMIN_SECRET")
PAYMENT_ID=$(deploy_contract "$PAYMENT_WASM" "$ADMIN_SECRET")

echo "Deployed contracts:" && echo "  Registry: $REGISTRY_ID" && echo "  Payment Executor: $PAYMENT_ID"

# ------------------------------------------------------------
# 6. Register company
# ------------------------------------------------------------
echo "Registering company..."
register_tx=$(stellar contract invoke \
  $REGISTRY_ID register_company \
  --args admin=$ADMIN_PUBLIC treasury=$TREASURY_PUBLIC \
  --network testnet \
  --source $ADMIN_SECRET 2>&1) || error "Company registration failed"
COMPANY_ID=$(echo "$register_tx" | grep -Eo '[0-9]+' | tail -n1)
if [[ -z "$COMPANY_ID" ]]; then
  error "Could not determine company ID from registration output"
fi

echo "Company registered with ID: $COMPANY_ID"

# ------------------------------------------------------------
# 7. Compile ZK circuits & generate commitment
# ------------------------------------------------------------
echo "Compiling ZK circuits and generating commitment..."
./scripts/compile_circuits.sh >/dev/null 2>&1 || error "Circuit compilation failed"
COMMITMENT=$(head -c 32 /dev/urandom | hexdump -v -e '/1 "%02x"')
COMMITMENT=$(printf "%064s" "$COMMITMENT" | tr ' ' '0')

echo "Generated commitment: $COMMITMENT"

# ------------------------------------------------------------
# 8. Add employee with commitment
# ------------------------------------------------------------
echo "Adding employee..."
stellar contract invoke \
  $REGISTRY_ID add_employee \
  --args company_id=$COMPANY_ID employee=$EMPLOYEE_PUBLIC commitment=$COMMITMENT \
  --network testnet \
  --source $ADMIN_SECRET >/dev/null 2>&1 || error "Adding employee failed"

echo "Employee added successfully."

# ------------------------------------------------------------
# 9. Fund treasury (optional minimal amount for payment)
# ------------------------------------------------------------
echo "Funding treasury for payment..."
stellar transaction create \
  $TREASURY_PUBLIC 1000 XLM \
  --network testnet \
  --source $ADMIN_SECRET >/dev/null 2>&1 || error "Funding treasury failed"

echo "Treasury funded."

# ------------------------------------------------------------
# 10. Generate payment proof (placeholder)
# ------------------------------------------------------------
PROOF="dummy_proof_$(date +%s)"

echo "Generated proof: $PROOF"

# ------------------------------------------------------------
# 11. Execute private payment
# ------------------------------------------------------------
echo "Executing private payment..."
stellar contract invoke \
  $PAYMENT_ID process_payment \
  --args company_id=$COMPANY_ID employee=$EMPLOYEE_PUBLIC proof=$PROOF \
  --network testnet \
  --source $ADMIN_SECRET >/dev/null 2>&1 || error "Payment execution failed"

echo "Payment executed successfully."

# ------------------------------------------------------------
# 12. Verification (simple placeholder)
# ------------------------------------------------------------
echo "Demo completed successfully."

# End of script
