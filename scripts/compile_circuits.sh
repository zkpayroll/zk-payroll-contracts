#!/bin/bash
set -e

# Directory setup
dir_circuits="$(dirname "$0")/../circuits"
dir_scripts="$(dirname "$0")"

# Main circuit file
template_circuit="$dir_circuits/payment.circom"
compiled_circuit="$dir_circuits/payment.r1cs"

# Phase 1 Powers of Tau file
ptau_file="$dir_circuits/powersOfTau28_hez_final_14.ptau"

# Output files
zkey_file="$dir_circuits/payment.zkey"
verification_key="$dir_circuits/verification_key.json"

# Download ptau if not present
if [ ! -f "$ptau_file" ]; then
    echo "Downloading ptau file..."
    wget -O "$ptau_file" https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_14.ptau
fi

# Compile circuit
if [ ! -f "$compiled_circuit" ]; then
    echo "Compiling payment.circom..."
    circom "$template_circuit" --r1cs --wasm --sym -o "$dir_circuits"
fi

# Groth16 setup
if [ ! -f "$zkey_file" ]; then
    echo "Running Groth16 setup..."
    snarkjs groth16 setup "$compiled_circuit" "$ptau_file" "$zkey_file"
fi

# Dummy Phase 2 contribution
snarkjs zkey contribute "$zkey_file" "$zkey_file" -e="dummy contributor"

# Export verification key
snarkjs zkey export verificationkey "$zkey_file" "$verification_key"

echo "All steps completed. Verification key at $verification_key"
