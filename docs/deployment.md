# Soroban Deployment and Contract Initialization Sequence

This guide explains how to deploy the ZK Payroll contract suite on the Soroban testnet and perform the initial admin configuration.

## Prerequisites
- Rust and Cargo installed
- `soroban-cli` installed and configured
- A funded testnet identity (e.g. `soroban config identity generate admin && soroban config identity fund admin --network testnet`)
- Network configuration set up (`soroban config network add testnet --rpc-url https://soroban-testnet.stellar.org:443 --network-passphrase "Test SDF Network ; September 2015"`)

## 1. Build Contracts
Compile all contracts into optimized Wasm:
```bash
cargo build --target wasm32-unknown-unknown --release
```

## 2. Deploy Contracts
Deploy the contracts in the following recommended order. Save the generated contract IDs (C...) as you will need them to wire the contracts together.

### Token Contract (Mock USDC or similar)
```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/soroban_token_contract.wasm \
  --source admin --network testnet
```
*(Export as `TOKEN_ID`)*

### Payroll Registry
```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/payroll_registry.wasm \
  --source admin --network testnet
```
*(Export as `REGISTRY_ID`)*

### Proof Verifier
```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/proof_verifier.wasm \
  --source admin --network testnet
```
*(Export as `VERIFIER_ID`)*

### Payment Executor
```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/payment_executor.wasm \
  --source admin --network testnet
```
*(Export as `EXECUTOR_ID`)*

## 3. Initialization and Wiring

Initialize the `payment_executor` with the addresses of the token, registry, and verifier contracts.

```bash
soroban contract invoke --id $EXECUTOR_ID --source admin --network testnet -- \
  initialize \
  --admin $(soroban config identity address admin) \
  --token $TOKEN_ID \
  --registry $REGISTRY_ID \
  --verifier $VERIFIER_ID
```

## 4. Smoke-test Checklist
1. **Register a Company**: Use the registry contract to create a new company record (providing the admin and treasury addresses).
2. **Add an Employee**: Add a Poseidon commitment for a test employee under the registered company.
3. **Submit a Payroll Proof**: Invoke the executor's payment method with a valid Groth16 proof, verifying that funds move from the treasury to the employee without errors.
4. **Replay Protection**: Attempt to submit the exact same proof again and verify it is rejected.
