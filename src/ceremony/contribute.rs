//! Contributor-side flow for a phase-2 ceremony.
//!
//! Wraps the BGM17 contribution math and the transcript data
//! layer into a single high-level operation a contributor (or the
//! contributor CLI) can call to extend a transcript with one
//! contribution. Pure orchestration; the cryptographic core lives
//! in [`super::bgm17`] and the data shape in [`super::transcript`].

use std::fs;
use std::io;
use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};

use crate::types::NodeId;

use super::bgm17::{apply_contribution, BgmError};
use super::transcript::{
    CircuitId, Contribution, Phase2Transcript, TranscriptError, TranscriptHash,
};

/// Errors surfaced by the contributor flow.
#[derive(Debug, thiserror::Error)]
pub enum ContributeError {
    #[error("io error reading or writing ceremony files: {0}")]
    Io(#[from] io::Error),

    #[error("failed to deserialise a ceremony artefact: {0}")]
    Deserialize(String),

    #[error("failed to serialise a ceremony artefact: {0}")]
    Serialize(String),

    #[error("BGM17 contribution failed: {0}")]
    Bgm(#[from] BgmError),

    #[error("transcript chain rejected the new contribution: {0}")]
    Transcript(#[from] TranscriptError),
}

/// Apply one contribution and return the updated proving key plus
/// the extended transcript. Pure orchestration of the cryptographic
/// pieces in [`super::bgm17`] and the data shape in
/// [`super::transcript`].
///
/// The caller supplies `prior_pk` and the previous `prior_transcript`
/// (or `None` for the very first contribution, in which case
/// `initial_srs_hash` seeds the transcript). `delta_i` is sampled
/// inside this function from `rng` and is dropped at the end of the
/// call so it does not outlive the stack frame; the caller's `rng`
/// remains the only entropy reference.
///
/// `contributor_pubkey` and `signature` on the resulting
/// Contribution are left empty in this commit; a follow-up PR
/// wires up signed attestations once the signing-key plumbing
/// lands. Verifiers built from this module check the DLEQ and
/// chain integrity regardless; signatures only add the
/// social-trust layer on top.
pub fn contribute<R: RngCore + CryptoRng>(
    mut prior_pk: ProvingKey<Bn254>,
    prior_transcript: Option<Phase2Transcript>,
    circuit: CircuitId,
    initial_srs_hash: TranscriptHash,
    contributor: NodeId,
    attestation: String,
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, Phase2Transcript), ContributeError> {
    let delta_i = Fr::rand(rng);
    let proof = apply_contribution(&mut prior_pk, delta_i, rng)?;

    let mut delta_after_g1 = Vec::new();
    prior_pk
        .delta_g1
        .serialize_compressed(&mut delta_after_g1)
        .map_err(|e| ContributeError::Serialize(format!("delta_after_g1: {}", e)))?;
    let mut delta_after_g2 = Vec::new();
    prior_pk
        .vk
        .delta_g2
        .serialize_compressed(&mut delta_after_g2)
        .map_err(|e| ContributeError::Serialize(format!("delta_after_g2: {}", e)))?;

    let mut transcript = prior_transcript
        .unwrap_or_else(|| Phase2Transcript::new(circuit.clone(), initial_srs_hash));
    let prior_hash = match transcript.contributions.last() {
        Some(prev) => super::transcript::hash_contribution(prev),
        None => transcript.initial_srs_hash,
    };

    let contribution = Contribution {
        prior_hash,
        contributor,
        delta_after_g1,
        delta_after_g2,
        dleq_proof: proof.to_bytes(),
        contributor_pubkey: Vec::new(),
        signature: Vec::new(),
        attestation,
    };
    transcript.append(contribution)?;

    Ok((prior_pk, transcript))
}

/// Read a `ProvingKey<Bn254>` from a compressed-arkworks file.
///
/// Trailing bytes are rejected: the file hash must bind 1-to-1 to
/// the deserialized key (callers hash the raw file bytes for
/// `initial_srs_hash`), so a file that deserializes to the same key
/// plus extra garbage is malformed, not a valid key.
pub fn read_pk(path: &Path) -> Result<ProvingKey<Bn254>, ContributeError> {
    let bytes = fs::read(path)?;
    let mut cursor = &bytes[..];
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|e| ContributeError::Deserialize(format!("ProvingKey at {:?}: {}", path, e)))?;
    if !cursor.is_empty() {
        return Err(ContributeError::Deserialize(format!(
            "ProvingKey at {:?}: {} trailing byte(s) after the ProvingKey",
            path,
            cursor.len()
        )));
    }
    Ok(pk)
}

/// Write a `ProvingKey<Bn254>` to a compressed-arkworks file.
pub fn write_pk(pk: &ProvingKey<Bn254>, path: &Path) -> Result<(), ContributeError> {
    write_compressed(pk, path)
}

/// Generic write of any `CanonicalSerialize` value as a
/// compressed-arkworks file. Used for both proving keys and the
/// verifying key the ceremony finalize binary extracts. Any
/// caller wanting a different on-disk format should not use this
/// helper — bincode-shaped artefacts go through
/// `write_transcript` instead.
/// Create the parent directories of `path` when they are missing,
/// so a fresh output directory does not fail a write after minutes
/// of ceremony computation. A bare filename (no parent) is a no-op.
fn ensure_parent_dir(path: &Path) -> Result<(), ContributeError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

pub fn write_compressed<T>(value: &T, path: &Path) -> Result<(), ContributeError>
where
    T: ark_serialize::CanonicalSerialize,
{
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|e| ContributeError::Serialize(format!("{:?}: {}", path, e)))?;
    ensure_parent_dir(path)?;
    fs::write(path, &bytes)?;
    Ok(())
}

/// Read a `Phase2Transcript` from a bincode file.
///
/// Trailing bytes are rejected, mirroring `read_pk`: the whole
/// file must be exactly one transcript.
pub fn read_transcript(path: &Path) -> Result<Phase2Transcript, ContributeError> {
    let bytes = fs::read(path)?;
    let mut cursor = io::Cursor::new(&bytes[..]);
    let transcript: Phase2Transcript = bincode::deserialize_from(&mut cursor).map_err(|e| {
        ContributeError::Deserialize(format!("Phase2Transcript at {:?}: {}", path, e))
    })?;
    if cursor.position() as usize != bytes.len() {
        return Err(ContributeError::Deserialize(format!(
            "Phase2Transcript at {:?}: {} trailing byte(s) after the transcript",
            path,
            bytes.len() - cursor.position() as usize
        )));
    }
    Ok(transcript)
}

/// Write a `Phase2Transcript` to a bincode file.
pub fn write_transcript(transcript: &Phase2Transcript, path: &Path) -> Result<(), ContributeError> {
    let bytes = bincode::serialize(transcript).map_err(|e| {
        ContributeError::Serialize(format!("Phase2Transcript to {:?}: {}", path, e))
    })?;
    ensure_parent_dir(path)?;
    fs::write(path, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::verifier::verify_phase2_transcript;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_snark::SNARK;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[derive(Clone)]
    struct TrivialCircuit;

    impl ConstraintSynthesizer<Fr> for TrivialCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(3u32)))?;
            let b = cs.new_witness_variable(|| Ok(Fr::from(5u32)))?;
            let c = cs.new_input_variable(|| Ok(Fr::from(15u32)))?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xCAFE_F00D_u64)
    }

    fn fresh_initial_pk() -> ProvingKey<Bn254> {
        let mut rng = rng();
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
        pk
    }

    #[test]
    fn one_contribution_extends_transcript_and_verifies() {
        let initial_pk = fresh_initial_pk();
        let mut rng = rng();
        let (after_pk, transcript) = contribute(
            initial_pk.clone(),
            None,
            CircuitId::Deposit,
            [0u8; 64],
            NodeId(vec![0x01]),
            "test contributor 1".to_string(),
            &mut rng,
        )
        .expect("first contribution succeeds");

        assert_eq!(transcript.len(), 1);
        assert_eq!(transcript.circuit, CircuitId::Deposit);
        assert_ne!(after_pk.delta_g1, initial_pk.delta_g1);
        verify_phase2_transcript(&initial_pk, &transcript).expect("transcript verifies");
    }

    #[test]
    fn two_chained_contributions_verify_end_to_end() {
        let initial_pk = fresh_initial_pk();
        let mut rng = rng();

        let (after_pk_1, transcript_1) = contribute(
            initial_pk.clone(),
            None,
            CircuitId::Transfer,
            [0u8; 64],
            NodeId(vec![0x01]),
            "first contributor".to_string(),
            &mut rng,
        )
        .expect("first contribution succeeds");

        let (after_pk_2, transcript_2) = contribute(
            after_pk_1,
            Some(transcript_1),
            CircuitId::Transfer,
            [0u8; 64],
            NodeId(vec![0x02]),
            "second contributor".to_string(),
            &mut rng,
        )
        .expect("second contribution succeeds");

        assert_eq!(transcript_2.len(), 2);
        assert_ne!(after_pk_2.delta_g1, initial_pk.delta_g1);
        verify_phase2_transcript(&initial_pk, &transcript_2)
            .expect("two-link chain verifies end-to-end");
    }

    fn fresh_transcript() -> Phase2Transcript {
        let initial_pk = fresh_initial_pk();
        let mut rng = rng();
        let (_pk, transcript) = contribute(
            initial_pk,
            None,
            CircuitId::Deposit,
            [0u8; 64],
            NodeId(vec![0x01]),
            "test contributor".to_string(),
            &mut rng,
        )
        .expect("contribution succeeds");
        transcript
    }

    #[test]
    fn read_pk_rejects_trailing_garbage_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pk_path = dir.path().join("pk.key");
        write_pk(&fresh_initial_pk(), &pk_path).expect("write pk");

        let mut bytes = fs::read(&pk_path).expect("read pk bytes");
        bytes.extend_from_slice(b"trailing garbage");
        fs::write(&pk_path, &bytes).expect("append garbage");

        let err = read_pk(&pk_path).expect_err("trailing bytes must be rejected");
        assert!(
            matches!(err, ContributeError::Deserialize(_)),
            "expected Deserialize error, got {:?}",
            err
        );
    }

    #[test]
    fn read_transcript_rejects_trailing_garbage_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tx_path = dir.path().join("transcript.bin");
        write_transcript(&fresh_transcript(), &tx_path).expect("write transcript");

        let mut bytes = fs::read(&tx_path).expect("read transcript bytes");
        bytes.extend_from_slice(b"trailing garbage");
        fs::write(&tx_path, &bytes).expect("append garbage");

        let err = read_transcript(&tx_path).expect_err("trailing bytes must be rejected");
        assert!(
            matches!(err, ContributeError::Deserialize(_)),
            "expected Deserialize error, got {:?}",
            err
        );
    }

    #[test]
    fn write_pk_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pk_path = dir.path().join("nested").join("deep").join("pk.key");
        let pk = fresh_initial_pk();

        write_pk(&pk, &pk_path).expect("write pk into missing parent dirs");
        let round_tripped = read_pk(&pk_path).expect("read back written pk");
        assert_eq!(round_tripped, pk);
    }

    #[test]
    fn write_transcript_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tx_path = dir.path().join("nested").join("deep").join("transcript.bin");
        let transcript = fresh_transcript();

        write_transcript(&transcript, &tx_path).expect("write transcript into missing parent dirs");
        let round_tripped = read_transcript(&tx_path).expect("read back written transcript");
        assert_eq!(round_tripped.len(), transcript.len());
        assert_eq!(round_tripped.circuit, transcript.circuit);
    }
}
