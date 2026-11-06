//! On-chain tests for `init_stake_token_vault` (#1356, Bug 2): the singleton
//! `stake_token_vault` PDA's mint is immutable once initialized, so the
//! instruction must verify the mint it is keyed to agrees with the registry's
//! pinned `stake_mint` — otherwise a wrong `STAKE_MINT` permanently bricks
//! dual-stake registration.
//!
//! The migration scenario needs a registry WITHOUT a vault, so the registry is
//! baked directly into genesis (at the dual-stake layout) instead of going
//! through `initialize_validator_registry`, which creates the vault inline.
//! Four cases: matching mint succeeds, mismatched mint is rejected and creates
//! no vault, a missing registry is rejected, and a pre-dual-stake (short)
//! registry — which has no mint to disagree with — still allows the vault to
//! be created.

use anchor_lang::prelude::*;
use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    program_pack::Pack,
    signature::Signer,
    system_program,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, entry, stake_vault_pdas};

fn init_vault_ix(
    program_id: Pubkey,
    authority: Pubkey,
    program_data: Pubkey,
    stake_mint: Pubkey,
) -> Instruction {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (vault, vault_authority) = stake_vault_pdas(program_id);
    Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            authority,
            stake_mint,
            validator_registry: registry_pda,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            program_data,
            token_program: spl_token::id(),
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    }
}

/// Bake a `ValidatorRegistry` at the current (dual-stake) layout into genesis,
/// pinning `stake_mint` — the state a migrated registry is in when the vault
/// migration runs. No vault account is baked.
fn bake_registry(pt: &mut ProgramTest, program_id: Pubkey, authority: Pubkey, stake_mint: Pubkey) {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let registry = ValidatorRegistry {
        authority,
        total_validators: 0,
        active_validators: 0,
        minimum_stake: 0,
        total_active_stake: 0,
        stake_mint,
        min_token_stake: 0,
    };
    let mut data = Vec::new();
    registry.try_serialize(&mut data).unwrap();
    assert_eq!(data.len(), 8 + ValidatorRegistry::INIT_SPACE);
    pt.add_account(
        registry_pda,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
}

/// Bake a pre-dual-stake registry: discriminator + the five original fields
/// only (72 bytes), no `stake_mint` / `min_token_stake` tail.
fn bake_legacy_registry(pt: &mut ProgramTest, program_id: Pubkey, authority: Pubkey) {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let mut data = Vec::new();
    data.extend_from_slice(&*ValidatorRegistry::DISCRIMINATOR);
    data.extend_from_slice(authority.as_ref());
    for _ in 0..4 {
        data.extend_from_slice(&0u64.to_le_bytes());
    }
    assert_eq!(data.len(), 72);
    pt.add_account(
        registry_pda,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
}

#[tokio::test]
async fn init_stake_token_vault_accepts_matching_mint() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    bake_registry(
        &mut pt,
        program_id,
        upgrade_authority.pubkey(),
        stake_mint,
    );

    let (mut banks, _payer, blockhash) = pt.start().await;

    let ix = init_vault_ix(
        program_id,
        upgrade_authority.pubkey(),
        program_data_pda,
        stake_mint,
    );
    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // The vault was created, keyed to the registry's mint.
    let (vault, vault_authority) = stake_vault_pdas(program_id);
    let vault_raw = banks.get_account(vault).await.unwrap().expect("vault created");
    let vault_state = spl_token::state::Account::unpack(&vault_raw.data).unwrap();
    assert_eq!(vault_state.mint, stake_mint, "vault keyed to the registry mint");
    assert_eq!(vault_state.owner, vault_authority, "vault owned by the vault authority");
    assert_eq!(vault_state.amount, 0, "vault starts empty");
}

#[tokio::test]
async fn init_stake_token_vault_rejects_mint_mismatching_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let registry_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let wrong_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    bake_registry(
        &mut pt,
        program_id,
        upgrade_authority.pubkey(),
        registry_mint,
    );

    let (mut banks, _payer, blockhash) = pt.start().await;

    // The operator passes a different STAKE_MINT than the registry pins.
    let ix = init_vault_ix(
        program_id,
        upgrade_authority.pubkey(),
        program_data_pda,
        wrong_mint,
    );
    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "a vault mint disagreeing with the registry must be rejected"
    );

    // The failed transaction rolled back: no vault was created, so a later
    // retry with the right mint can still succeed.
    let (vault, _) = stake_vault_pdas(program_id);
    assert!(
        banks.get_account(vault).await.unwrap().is_none(),
        "rejected init must not leave a bricked vault behind"
    );
}

#[tokio::test]
async fn init_stake_token_vault_rejects_missing_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    // No registry baked at all.

    let (mut banks, _payer, blockhash) = pt.start().await;

    let ix = init_vault_ix(
        program_id,
        upgrade_authority.pubkey(),
        program_data_pda,
        stake_mint,
    );
    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "init without an initialized registry must be rejected"
    );
}

#[tokio::test]
async fn init_stake_token_vault_accepts_short_legacy_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    // Pre-dual-stake registry: no stake_mint field, so nothing to disagree with.
    bake_legacy_registry(&mut pt, program_id, upgrade_authority.pubkey());

    let (mut banks, _payer, blockhash) = pt.start().await;

    let ix = init_vault_ix(
        program_id,
        upgrade_authority.pubkey(),
        program_data_pda,
        stake_mint,
    );
    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let (vault, _) = stake_vault_pdas(program_id);
    let vault_raw = banks.get_account(vault).await.unwrap().expect("vault created");
    let vault_state = spl_token::state::Account::unpack(&vault_raw.data).unwrap();
    assert_eq!(vault_state.mint, stake_mint, "vault keyed to the passed mint");
}
