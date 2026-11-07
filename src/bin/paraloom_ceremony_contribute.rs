//! Phase-2 ceremony contributor CLI.
//!
//! Reads the previous proving key and (optionally) transcript,
//! samples this contributor's `δ_i` from OS entropy, applies the
//! BGM17 contribution, appends the resulting record to the
//! transcript, and writes the new proving key plus extended
//! transcript to the supplied output paths. Tracking issue #64.
//!
//! Omit --prior-transcript on the very first contribution; the
//! binary then seeds a fresh transcript from --circuit, anchored at
//! the SHA-512 of --prior-pk (--initial-srs-hash may be supplied to
//! pin the anchor explicitly, but must match that hash).

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use paraloom::ceremony::{
    contribute, hash_pk, read_pk, read_transcript, try_hash_from_hex, write_pk, write_transcript,
    CircuitId,
};
use paraloom::types::NodeId;
use rand::rngs::OsRng;

#[derive(Parser, Debug)]
#[command(
    name = "paraloom-ceremony-contribute",
    about = "Apply one phase-2 ceremony contribution and extend the transcript"
)]
struct Args {
    /// Path to the previous proving key file (compressed-arkworks).
    #[arg(long)]
    prior_pk: PathBuf,

    /// Path to the previous transcript file (bincode). Omit on the
    /// very first contribution.
    #[arg(long)]
    prior_transcript: Option<PathBuf>,

    /// Output path for the new proving key.
    #[arg(long)]
    output_pk: PathBuf,

    /// Output path for the extended transcript.
    #[arg(long)]
    output_transcript: PathBuf,

    /// Which circuit this transcript covers. Only used when
    /// --prior-transcript is omitted.
    #[arg(long, default_value = "deposit")]
    circuit: String,

    /// Hex-encoded SHA-512 of the initial SRS. Only meaningful when
    /// --prior-transcript is omitted; the value is committed to the
    /// new transcript as the chain anchor. If unset, the anchor is
    /// computed from --prior-pk (`hash_pk`); a supplied value that
    /// does not match the prior key is rejected, since finalize and
    /// verify would later refuse the transcript with
    /// `initial_srs_hash mismatch`.
    #[arg(long)]
    initial_srs_hash: Option<String>,

    /// Hex-encoded NodeId of this contributor. Round-trips through
    /// NodeId's Display/FromStr impls.
    #[arg(long)]
    contributor_hex: String,

    /// Free-form attestation describing what this contributor did
    /// (hardware, OS, witnesses). Public, audit-only.
    #[arg(long)]
    attestation: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let circuit =
        CircuitId::from_str(&args.circuit).map_err(|e| anyhow::anyhow!("--circuit: {}", e))?;
    let contributor =
        NodeId::from_str(&args.contributor_hex).context("--contributor-hex is not valid hex")?;

    let prior_pk = read_pk(&args.prior_pk)?;
    let prior_transcript = match &args.prior_transcript {
        Some(path) => Some(read_transcript(path)?),
        None => None,
    };

    // The first contribution anchors the transcript at the SHA-512 of
    // the initial proving key. Defaulting to the all-zero hash — or
    // accepting a caller-supplied hash unchecked — produces a
    // transcript finalize/verify later reject with
    // `initial_srs_hash mismatch`, so resolve the anchor from the key
    // itself and refuse a supplied value that disagrees with it. When
    // a prior transcript exists the anchor is already fixed inside it
    // and this value is unused.
    let initial_srs_hash = match args.initial_srs_hash.as_deref() {
        Some(hex) => {
            let supplied =
                try_hash_from_hex(hex).map_err(|e| anyhow::anyhow!("--initial-srs-hash: {}", e))?;
            if prior_transcript.is_none() {
                let expected = hash_pk(&prior_pk);
                if supplied != expected {
                    return Err(anyhow::anyhow!(
                        "--initial-srs-hash does not match the SHA-512 of --prior-pk (expected {})",
                        hex::encode(expected)
                    ));
                }
            }
            supplied
        }
        None => {
            if prior_transcript.is_none() {
                hash_pk(&prior_pk)
            } else {
                [0u8; 64]
            }
        }
    };

    let mut rng = OsRng;
    let (new_pk, new_transcript) = contribute(
        prior_pk,
        prior_transcript,
        circuit,
        initial_srs_hash,
        contributor,
        args.attestation,
        &mut rng,
    )?;

    write_pk(&new_pk, &args.output_pk)?;
    write_transcript(&new_transcript, &args.output_transcript)?;

    println!(
        "Contribution applied. Transcript length: {}",
        new_transcript.len()
    );
    Ok(())
}
