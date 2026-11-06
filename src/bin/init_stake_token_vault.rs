//! Create the shared dual-stake `stake_token_vault` for a registry that predates
//! the dual-stake fields.
//!
//! `initialize_validator_registry` creates the vault inline, but a registry
//! initialized by the pre-dual-stake program has no vault and its PDA already
//! exists, so that instruction can never run again. This bin calls the
//! `init_stake_token_vault` migration instruction (upgrade-authority-gated) to
//! create the vault once, keyed to the same mint `reset_validator_registry`
//! pins into the registry. Run it once on the ceremony-key redeploy, before any
//! dual-stake `register_validator`.
//!
//! Pre-flight (#1356): reads the on-chain registry first and refuses to submit
//! when its pinned `stake_mint` disagrees with STAKE_MINT — the singleton
//! vault's mint is immutable once created, so a mismatch would permanently
//! brick dual-stake registration.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the program's upgrade authority (signer)
//!   STAKE_MINT                     the dual-stake token mint to key the vault to

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;
    let stake_mint = Pubkey::from_str(&std::env::var("STAKE_MINT")?)?;

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // The vault's token program must be the one that owns the mint (classic SPL
    // Token or Token-2022); read it rather than assume, so the vault's
    // `token::token_program` matches what `register_validator` will pass.
    let token_program = client.get_account(&stake_mint)?.owner;

    let (vault, _) = derive_stake_token_vault(&program_id);
    let (registry_pda, _) = derive_validator_registry(&program_id);

    // Pre-flight (#1356): the on-chain instruction now fails closed unless the
    // registry exists and — once it is at the dual-stake layout with a mint
    // pinned — its pinned mint equals STAKE_MINT. Catch a bad mint here so a
    // doomed transaction is never submitted. Layout: 8-byte discriminator +
    // authority (32) + 4 x u64 + stake_mint (32) at bytes 72..104.
    match client.get_account(&registry_pda) {
        Ok(registry) => {
            if registry.owner != program_id {
                return Err(format!(
                    "validator registry {registry_pda} is owned by {} (expected the bridge program {program_id}); refusing to create the vault",
                    registry.owner
                )
                .into());
            }
            if registry.data.len() >= 112 {
                let pinned = Pubkey::new_from_array(
                    registry.data[72..104]
                        .try_into()
                        .expect("registry at dual-stake layout carries stake_mint at 72..104"),
                );
                if pinned != Pubkey::default() && pinned != stake_mint {
                    return Err(format!(
                        "STAKE_MINT {stake_mint} does not match the validator registry's pinned stake mint {pinned}; initializing the vault with this mint would permanently brick dual-stake registration"
                    )
                    .into());
                }
            }
        }
        Err(e) => {
            return Err(format!(
                "validator registry {registry_pda} is not readable ({e}); initialize the registry before creating the stake token vault"
            )
            .into());
        }
    }

    println!("=== init stake token vault ===");
    println!("Program:       {program_id}");
    println!("Authority:     {}", authority.pubkey());
    println!("Stake mint:    {stake_mint}");
    println!("Token program: {token_program}");
    println!("Registry PDA:  {registry_pda}");
    println!("Vault PDA:     {vault}");

    if client.get_account(&vault).is_ok() {
        println!("\nVault already exists — nothing to do.");
        return Ok(());
    }

    let ix = create_init_stake_token_vault_instruction(
        &program_id,
        &authority.pubkey(),
        &stake_mint,
        &token_program,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending init_stake_token_vault...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Vault created. Signature: {sig}");

    Ok(())
}
