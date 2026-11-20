//! On-chain test for `reconcile_orphaned_validator` (#1625).
//!
//! Reproduces the issue's walkthrough: two validators registered at 1 SOL
//! each, then `reset_validator_registry` rebuilds the counters from only
//! validator A — validator B's PDA is left `is_active` with its stake, but
//! already excluded from the rebuilt registry. Reconciling B must clear the
//! orphaned PDA (inactive, stake routed to unbonding) WITHOUT touching the
//! registry counters: the old documented procedure (`deactivate_validator`)
//! unconditionally decremented them and drove `total_active_stake` below the
//! real active stake, so the next settlement bricked with `QuorumNotMet`.
//! Also asserts a second reconcile reverts (`ValidatorNotActive`) and that a
//! non-authority caller is rejected by the registry `has_one` gate.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account, instruction::AccountMeta, instruction::Instruction, signature::Keypair,
    signature::Signer, system_program, transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

fn register_ix(
    program_id: Pubkey,
    registry_pda: Pubkey,
    validator: Pubkey,
    stake_mint: Pubkey,
    validator_token: Pubkey,
) -> (Instruction, Pubkey) {
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.as_ref()], &program_id);
    let ix = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: MIN_VALIDATOR_STAKE,
            token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator,
            stake_mint,
            validator_token_account: validator_token,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            token_program: spl_token::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    (ix, validator_pda)
}

fn reconcile_ix(
    program_id: Pubkey,
    registry_pda: Pubkey,
    validator_pda: Pubkey,
    authority: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        data: instruction::ReconcileOrphanedValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: validator_pda,
            validator_registry: registry_pda,
            authority,
        }
        .to_account_metas(None),
    }
}

fn init_registry_ix(
    program_id: Pubkey,
    registry_pda: Pubkey,
    stake_mint: Pubkey,
    authority: Pubkey,
    program_data_pda: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
            stake_mint,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            stake_vault_authority: Pubkey::find_program_address(
                &[b"stake_vault_authority"],
                &program_id,
            )
            .0,
            token_program: spl_token::id(),
            rent: solana_sdk::sysvar::rent::ID,
            validator_registry: registry_pda,
            authority,
            program_data: program_data_pda,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    }
}

fn fund_validator(pt: &mut ProgramTest, validator: &Keypair) {
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 5 * MIN_VALIDATOR_STAKE,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
}

#[tokio::test]
async fn reconcile_orphaned_validator_leaves_registry_counters_intact() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let registry_pda =
        Pubkey::find_program_address(&[b"validator_registry"], &program_id).0;

    let validator_a = Keypair::new();
    let validator_b = Keypair::new();
    fund_validator(&mut pt, &validator_a);
    fund_validator(&mut pt, &validator_b);
    let token_a = add_token_account(
        &mut pt,
        stake_mint,
        validator_a.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let token_b = add_token_account(
        &mut pt,
        stake_mint,
        validator_b.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let (mut banks, _payer, blockhash) = pt.start().await;

    // Init registry.
    let init_ix = init_registry_ix(
        program_id,
        registry_pda,
        stake_mint,
        upgrade_authority.pubkey(),
        program_data_pda,
    );
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Register A and B (1 SOL each).
    let (reg_a, pda_a) = register_ix(
        program_id,
        registry_pda,
        validator_a.pubkey(),
        stake_mint,
        token_a,
    );
    let mut tx = Transaction::new_with_payer(&[reg_a], Some(&validator_a.pubkey()));
    tx.sign(&[&validator_a], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let (reg_b, pda_b) = register_ix(
        program_id,
        registry_pda,
        validator_b.pubkey(),
        stake_mint,
        token_b,
    );
    let mut tx = Transaction::new_with_payer(&[reg_b], Some(&validator_b.pubkey()));
    tx.sign(&[&validator_b], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Reset the registry keeping ONLY validator A (declare one). B's PDA is
    // now orphaned: still is_active with 1 SOL, already excluded from the
    // rebuilt counters.
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: system_program::ID,
    }
    .to_account_metas(None);
    reset_metas.push(AccountMeta::new_readonly(pda_a, false));
    let reset_ix = Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            expected_active_validators: 1,
        }
        .data(),
        accounts: reset_metas,
    };
    let mut tx = Transaction::new_with_payer(&[reset_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let after_reset = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(after_reset.active_validators, 1);
    assert_eq!(after_reset.total_active_stake, MIN_VALIDATOR_STAKE);
    let raw = banks.get_account(pda_b).await.unwrap().unwrap();
    let orphan = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(orphan.is_active, "excluded validator PDA stays active after reset");
    assert_eq!(orphan.stake_amount, MIN_VALIDATOR_STAKE);

    // Reconcile the orphan. Counters must NOT move: B's stake was already
    // excluded by the reset, so any decrement here is the #1625 double-count.
    let ix = reconcile_ix(
        program_id,
        registry_pda,
        pda_b,
        upgrade_authority.pubkey(),
    );
    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let after = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        after.active_validators, 1,
        "reconcile must not decrement the already-rebuilt count"
    );
    assert_eq!(
        after.total_active_stake, MIN_VALIDATOR_STAKE,
        "reconcile must not double-subtract the orphan's stake"
    );

    // The orphaned PDA itself is cleaned up: inactive, stake zeroed, stake
    // routed into unbonding for later withdrawal.
    let raw = banks.get_account(pda_b).await.unwrap().unwrap();
    let reconciled = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(!reconciled.is_active);
    assert_eq!(reconciled.stake_amount, 0);
    assert_eq!(reconciled.unbonding_amount, MIN_VALIDATOR_STAKE);
    assert!(reconciled.unbonding_slot > 0);

    // A second reconcile on the same PDA reverts: nothing left to reconcile.
    // (Fresh blockhash: an identical re-send of the first tx would carry the
    // same signature and be dropped as a duplicate without re-executing.)
    let blockhash = banks.get_latest_blockhash().await.unwrap();
    let ix = reconcile_ix(
        program_id,
        registry_pda,
        pda_b,
        upgrade_authority.pubkey(),
    );
    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    assert!(
        banks.process_transaction(tx).await.is_err(),
        "reconciling an already-inactive validator must fail"
    );
}

#[tokio::test]
async fn reconcile_orphaned_validator_rejects_non_authority() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let registry_pda =
        Pubkey::find_program_address(&[b"validator_registry"], &program_id).0;

    let validator_a = Keypair::new();
    fund_validator(&mut pt, &validator_a);
    let token_a = add_token_account(
        &mut pt,
        stake_mint,
        validator_a.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let (mut banks, payer, blockhash) = pt.start().await;

    let init_ix = init_registry_ix(
        program_id,
        registry_pda,
        stake_mint,
        upgrade_authority.pubkey(),
        program_data_pda,
    );
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let (reg_a, pda_a) = register_ix(
        program_id,
        registry_pda,
        validator_a.pubkey(),
        stake_mint,
        token_a,
    );
    let mut tx = Transaction::new_with_payer(&[reg_a], Some(&validator_a.pubkey()));
    tx.sign(&[&validator_a], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // The payer is NOT the registry authority: the reconcile must fail on
    // the shared DeactivateValidator `has_one = authority` gate.
    let ix = reconcile_ix(program_id, registry_pda, pda_a, payer.pubkey());
    let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    assert!(
        banks.process_transaction(tx).await.is_err(),
        "non-authority reconcile must fail"
    );
    // And the validator is untouched by the rejected call.
    let raw = banks.get_account(pda_a).await.unwrap().unwrap();
    let untouched = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(untouched.is_active);
    assert_eq!(untouched.stake_amount, MIN_VALIDATOR_STAKE);
}
