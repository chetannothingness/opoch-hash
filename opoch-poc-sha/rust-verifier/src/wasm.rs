//! WASM Verifier Module
//!
//! Provides WebAssembly bindings for browser-based proof verification.
//!
//! Build with:
//!   wasm-pack build --release --target web
//!
//! Usage in JavaScript:
//!   import init, { verify_chain, extract_d0, extract_y, extract_n } from './pkg/opoch_verifier.js';
//!   await init();
//!   const valid = verify_chain(proofBytes, d0Hex, yHex, n);

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::proof::OpochProof;
use crate::endtoend::production_fri_config;
use crate::fri::FriVerifier;
use crate::transcript::Transcript;

/// Verify an OPOCH proof
///
/// # Arguments
/// * `proof_bytes` - The serialized proof (312 bytes)
/// * `d0_hex` - The claimed initial hash as hex string (64 chars)
/// * `y_hex` - The claimed final hash as hex string (64 chars)
/// * `n` - The claimed chain length
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn verify_chain(proof_bytes: &[u8], d0_hex: &str, y_hex: &str, n: u64) -> bool {
    verify_chain_internal(proof_bytes, d0_hex, y_hex, n)
}

/// Non-WASM version for testing
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_chain(proof_bytes: &[u8], d0_hex: &str, y_hex: &str, n: u64) -> bool {
    verify_chain_internal(proof_bytes, d0_hex, y_hex, n)
}

fn verify_chain_internal(proof_bytes: &[u8], d0_hex: &str, y_hex: &str, n: u64) -> bool {
    // Parse proof
    let proof = match OpochProof::deserialize(proof_bytes) {
        Some(p) => p,
        None => return false,
    };

    // Parse d0
    let d0 = match hex::decode(d0_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return false,
    };

    // Parse y
    let y = match hex::decode(y_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return false,
    };

    // Verify header bindings
    if proof.header.d0 != d0 {
        return false;
    }
    if proof.header.y != y {
        return false;
    }
    if proof.header.n != n {
        return false;
    }

    // Verify chain bindings in final proof
    if proof.final_proof.chain_start != proof.header.d0 {
        return false;
    }
    if proof.final_proof.chain_end != proof.header.y {
        return false;
    }

    // Verify FRI proof
    let mut transcript = Transcript::new();
    transcript.append_commitment(&proof.final_proof.children_root);
    transcript.append(&proof.final_proof.chain_start);
    transcript.append(&proof.final_proof.chain_end);

    // CRITICAL: Must call challenge_aggregation to match prover's transcript state
    let _alpha = transcript.challenge_aggregation();

    let fri_config = production_fri_config();
    let fri_verifier = FriVerifier::new(fri_config);

    fri_verifier.verify(&proof.final_proof.fri_proof, &mut transcript)
}

/// Extract d0 from a proof
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn extract_d0(proof_bytes: &[u8]) -> Option<String> {
    extract_d0_internal(proof_bytes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn extract_d0(proof_bytes: &[u8]) -> Option<String> {
    extract_d0_internal(proof_bytes)
}

fn extract_d0_internal(proof_bytes: &[u8]) -> Option<String> {
    let proof = OpochProof::deserialize(proof_bytes)?;
    Some(hex::encode(proof.header.d0))
}

/// Extract y from a proof
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn extract_y(proof_bytes: &[u8]) -> Option<String> {
    extract_y_internal(proof_bytes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn extract_y(proof_bytes: &[u8]) -> Option<String> {
    extract_y_internal(proof_bytes)
}

fn extract_y_internal(proof_bytes: &[u8]) -> Option<String> {
    let proof = OpochProof::deserialize(proof_bytes)?;
    Some(hex::encode(proof.header.y))
}

/// Extract n from a proof
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn extract_n(proof_bytes: &[u8]) -> Option<u64> {
    extract_n_internal(proof_bytes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn extract_n(proof_bytes: &[u8]) -> Option<u64> {
    extract_n_internal(proof_bytes)
}

fn extract_n_internal(proof_bytes: &[u8]) -> Option<u64> {
    let proof = OpochProof::deserialize(proof_bytes)?;
    Some(proof.header.n)
}

/// Get verifier version
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn verifier_version() -> String {
    "1.0.0".to_string()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verifier_version() -> String {
    "1.0.0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_verify_chain() {
        // Load test proof
        let proof_bytes = fs::read("public_bundle/vectors/poc_N_2K_proof.bin")
            .expect("Test proof not found");

        let stmt_str = fs::read_to_string("public_bundle/vectors/poc_N_2K_stmt.json")
            .expect("Test statement not found");
        let stmt: serde_json::Value = serde_json::from_str(&stmt_str).unwrap();

        let d0 = stmt["d0"].as_str().unwrap();
        let y = stmt["y"].as_str().unwrap();
        let n = stmt["n"].as_u64().unwrap();

        let valid = verify_chain(&proof_bytes, d0, y, n);
        assert!(valid, "Valid proof should verify");
    }

    #[test]
    fn test_extract_functions() {
        let proof_bytes = fs::read("public_bundle/vectors/poc_N_2K_proof.bin")
            .expect("Test proof not found");

        let d0 = extract_d0(&proof_bytes).expect("Should extract d0");
        let y = extract_y(&proof_bytes).expect("Should extract y");
        let n = extract_n(&proof_bytes).expect("Should extract n");

        assert_eq!(d0.len(), 64);
        assert_eq!(y.len(), 64);
        assert_eq!(n, 2048);
    }

    #[test]
    fn test_reject_wrong_d0() {
        let proof_bytes = fs::read("public_bundle/vectors/poc_N_2K_proof.bin")
            .expect("Test proof not found");

        let stmt_str = fs::read_to_string("public_bundle/vectors/poc_N_2K_stmt.json")
            .expect("Test statement not found");
        let stmt: serde_json::Value = serde_json::from_str(&stmt_str).unwrap();

        // Use wrong d0
        let wrong_d0 = "0000000000000000000000000000000000000000000000000000000000000000";
        let y = stmt["y"].as_str().unwrap();
        let n = stmt["n"].as_u64().unwrap();

        let valid = verify_chain(&proof_bytes, wrong_d0, y, n);
        assert!(!valid, "Wrong d0 should fail");
    }

    #[test]
    fn test_reject_corrupted_proof() {
        let mut proof_bytes = fs::read("public_bundle/vectors/poc_N_2K_proof.bin")
            .expect("Test proof not found");

        let stmt_str = fs::read_to_string("public_bundle/vectors/poc_N_2K_stmt.json")
            .expect("Test statement not found");
        let stmt: serde_json::Value = serde_json::from_str(&stmt_str).unwrap();

        let d0 = stmt["d0"].as_str().unwrap();
        let y = stmt["y"].as_str().unwrap();
        let n = stmt["n"].as_u64().unwrap();

        // Corrupt the chain_start (bytes 168-199) - this is checked
        proof_bytes[170] ^= 0xFF;

        let valid = verify_chain(&proof_bytes, d0, y, n);
        assert!(!valid, "Corrupted proof should fail");
    }
}
