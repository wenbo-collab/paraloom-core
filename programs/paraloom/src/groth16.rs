//! Vendored Groth16 (BN254) verifier over Solana's `alt_bn128` syscalls.
//!
//! Source: <https://github.com/Lightprotocol/groth16-solana> (MIT), trimmed to
//! the verify path. Proofs are produced off-chain by the workspace prover in
//! the `alt_bn128` wire form (big-endian coordinates, G2 `c1`/`c0` ordering,
//! negated `proof_a`); this only checks them.
#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};

#[derive(Debug, PartialEq, Eq)]
pub enum Groth16Error {
    InvalidPublicInputsLength,
    PublicInputGreaterThanFieldSize,
    PreparingInputsG1MulFailed,
    PreparingInputsG1AdditionFailed,
    ProofVerificationFailed,
}

pub struct Groth16Verifyingkey<'a> {
    pub nr_pubinputs: usize,
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamme_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: &'a [[u8; 64]],
}

pub struct Groth16Verifier<'a, const NR_INPUTS: usize> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],
    public_inputs: &'a [[u8; 32]; NR_INPUTS],
    prepared_public_inputs: [u8; 64],
    verifyingkey: &'a Groth16Verifyingkey<'a>,
}

impl<const NR_INPUTS: usize> Groth16Verifier<'_, NR_INPUTS> {
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifyingkey: &'a Groth16Verifyingkey<'a>,
    ) -> Result<Groth16Verifier<'a, NR_INPUTS>, Groth16Error> {
        // `prepare_inputs` indexes `vk_ic[0]` directly, so an empty IC vector
        // would panic; `nr_pubinputs` must agree with the supplied inputs and
        // with the IC length, or verification silently binds the wrong key (#1383).
        if verifyingkey.vk_ic.is_empty()
            || verifyingkey.nr_pubinputs != public_inputs.len()
            || public_inputs.len().checked_add(1) != Some(verifyingkey.vk_ic.len())
        {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }
        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifyingkey,
        })
    }

    fn prepare_inputs(&mut self) -> Result<(), Groth16Error> {
        let mut prepared = self.verifyingkey.vk_ic[0];
        for (i, input) in self.public_inputs.iter().enumerate() {
            if !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThanFieldSize);
            }
            let mul_res = alt_bn128_multiplication(
                &[&self.verifyingkey.vk_ic[i + 1][..], &input[..]].concat(),
            )
            .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
            prepared = alt_bn128_addition(&[&mul_res[..], &prepared[..]].concat())
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?[..]
                .try_into()
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        }
        self.prepared_public_inputs = prepared;
        Ok(())
    }

    pub fn verify(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_inputs()?;
        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifyingkey.vk_gamme_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifyingkey.vk_delta_g2.as_slice(),
            self.verifyingkey.vk_alpha_g1.as_slice(),
            self.verifyingkey.vk_beta_g2.as_slice(),
        ]
        .concat();
        let res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| Groth16Error::ProofVerificationFailed)?;
        if res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(true)
    }
}

fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    BigUint::from_bytes_be(bytes) < Fr::MODULUS.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_new_rejects_inconsistent_verifying_key() {
        let a = [0u8; 64];
        let b = [0u8; 128];
        let c = [0u8; 64];
        let inputs: [[u8; 32]; 2] = [[0u8; 32]; 2];
        let ic: Vec<[u8; 64]> = vec![[0u8; 64]; 3];

        // Empty IC vector: prepare_inputs would index vk_ic[0] and panic (#1383).
        let empty_vk = Groth16Verifyingkey {
            nr_pubinputs: 0,
            vk_alpha_g1: a,
            vk_beta_g2: b,
            vk_gamme_g2: b,
            vk_delta_g2: b,
            vk_ic: &[],
        };
        assert!(Groth16Verifier::new(&a, &b, &c, &inputs, &empty_vk).is_err());

        // nr_pubinputs disagreeing with the supplied inputs (#1383).
        let mismatched_vk = Groth16Verifyingkey {
            nr_pubinputs: 1,
            vk_alpha_g1: a,
            vk_beta_g2: b,
            vk_gamme_g2: b,
            vk_delta_g2: b,
            vk_ic: &ic,
        };
        assert!(Groth16Verifier::new(&a, &b, &c, &inputs, &mismatched_vk).is_err());

        // Consistent key (2 inputs, nr_pubinputs 2, 3 IC points) is accepted.
        let good_vk = Groth16Verifyingkey {
            nr_pubinputs: 2,
            vk_alpha_g1: a,
            vk_beta_g2: b,
            vk_gamme_g2: b,
            vk_delta_g2: b,
            vk_ic: &ic,
        };
        assert!(Groth16Verifier::new(&a, &b, &c, &inputs, &good_vk).is_ok());
    }
}
