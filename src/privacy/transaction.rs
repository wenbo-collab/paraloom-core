//! Shielded transaction types
//!
//! Three main transaction types:
//! 1. Deposit: Public -> Private (mint shielded coins)
//! 2. Transfer: Private -> Private (shielded transfer)
//! 3. Withdraw: Private -> Public (burn shielded coins)

use crate::privacy::types::{Commitment, Note, Nullifier, ShieldedAddress};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A shielded transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ShieldedTransaction {
    /// Deposit public funds into shielded pool
    Deposit(DepositTx),

    /// Transfer within shielded pool
    Transfer(TransferTx),

    /// Withdraw from shielded pool to public
    Withdraw(WithdrawTx),
}

impl ShieldedTransaction {
    /// Get transaction ID
    pub fn id(&self) -> String {
        match self {
            ShieldedTransaction::Deposit(tx) => tx.tx_id.clone(),
            ShieldedTransaction::Transfer(tx) => tx.tx_id.clone(),
            ShieldedTransaction::Withdraw(tx) => tx.tx_id.clone(),
        }
    }

    /// Get fee amount
    pub fn fee(&self) -> u64 {
        match self {
            ShieldedTransaction::Deposit(tx) => tx.fee,
            ShieldedTransaction::Transfer(tx) => tx.fee,
            ShieldedTransaction::Withdraw(tx) => tx.fee,
        }
    }
}

/// Deposit transaction: Public -> Private
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositTx {
    /// Transaction ID
    pub tx_id: String,

    /// Public sender address (on Solana/bridge)
    pub from_public: Vec<u8>,

    /// Amount being deposited (in lamports)
    pub amount: u64,

    /// Output commitment (recipient's shielded note)
    pub output_commitment: Commitment,

    /// Output note (encrypted for recipient)
    pub output_note: Note,

    /// Transaction fee
    pub fee: u64,

    /// Timestamp
    pub timestamp: u64,
}

impl DepositTx {
    /// Create a new deposit transaction
    pub fn new(
        from_public: Vec<u8>,
        amount: u64,
        recipient: ShieldedAddress,
        randomness: [u8; 32],
        fee: u64,
    ) -> Self {
        Self::new_asset(
            from_public,
            amount,
            recipient,
            randomness,
            fee,
            crate::privacy::types::NATIVE_SOL_ASSET,
        )
    }

    /// Asset-aware deposit (#237): the output note carries `asset_id` (the
    /// SPL mint's bytes, or `NATIVE_SOL_ASSET` for native SOL), so an SPL
    /// deposit is indexed into the pool under its asset and can later be
    /// withdrawn through `withdraw_spl`.
    pub fn new_asset(
        from_public: Vec<u8>,
        amount: u64,
        recipient: ShieldedAddress,
        randomness: [u8; 32],
        fee: u64,
        asset_id: crate::privacy::types::AssetId,
    ) -> Self {
        let tx_id = uuid::Uuid::new_v4().to_string();
        // Saturating subtraction: a fee larger than the amount must not panic
        // with an integer underflow (verify() then rejects it as invalid).
        let output_note = Note::new(recipient, amount.saturating_sub(fee), randomness, asset_id);
        let output_commitment = output_note.commitment();

        // A pre-epoch clock must not panic the constructor; fall back to 0.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        DepositTx {
            tx_id,
            from_public,
            amount,
            output_commitment,
            output_note,
            fee,
            timestamp,
        }
    }

    /// Verify deposit transaction
    pub fn verify(&self) -> bool {
        // Zero-amount deposits and deposits with no sender are invalid.
        if self.amount == 0 {
            return false;
        }
        if self.from_public.is_empty() {
            return false;
        }

        // Check amount covers fee
        if self.amount < self.fee {
            return false;
        }

        // Check commitment matches note
        if self.output_commitment != self.output_note.commitment() {
            return false;
        }

        // Check note amount is correct (amount - fee)
        if self.output_note.amount != self.amount - self.fee {
            return false;
        }

        true
    }
}

/// Transfer transaction: Private -> Private
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferTx {
    /// Transaction ID
    pub tx_id: String,

    /// Input nullifiers (spending previous notes)
    pub input_nullifiers: Vec<Nullifier>,

    /// Output commitments (new notes for recipients)
    pub output_commitments: Vec<Commitment>,

    /// Output notes (encrypted for recipients)
    pub output_notes: Vec<Note>,

    /// ZK proof (proves transaction is valid)
    /// Placeholder - will be replaced with actual proof system
    pub zk_proof: Vec<u8>,

    /// Merkle root at time of transaction (anchors the proof)
    pub merkle_root: [u8; 32],

    /// Transaction fee
    pub fee: u64,

    /// Timestamp
    pub timestamp: u64,
}

impl TransferTx {
    /// Create a new transfer transaction
    pub fn new(
        input_nullifiers: Vec<Nullifier>,
        output_notes: Vec<Note>,
        merkle_root: [u8; 32],
        fee: u64,
    ) -> Self {
        let tx_id = uuid::Uuid::new_v4().to_string();

        let output_commitments: Vec<Commitment> =
            output_notes.iter().map(|note| note.commitment()).collect();

        // A pre-epoch clock must not panic the constructor; fall back to 0.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        TransferTx {
            tx_id,
            input_nullifiers,
            output_commitments,
            output_notes,
            zk_proof: Vec::new(), // Placeholder
            merkle_root,
            fee,
            timestamp,
        }
    }

    /// Verify transfer transaction structure
    pub fn verify_structure(&self) -> bool {
        // Must have inputs and outputs
        if self.input_nullifiers.is_empty() || self.output_commitments.is_empty() {
            return false;
        }

        // No nullifier or commitment may repeat within one transfer: a
        // duplicated input spends the same note twice, and a duplicated
        // output commitment mints the same note twice.
        let mut seen_nullifiers = HashSet::new();
        if !self
            .input_nullifiers
            .iter()
            .all(|n| seen_nullifiers.insert(n))
        {
            return false;
        }
        let mut seen_commitments = HashSet::new();
        if !self
            .output_commitments
            .iter()
            .all(|c| seen_commitments.insert(c))
        {
            return false;
        }

        // Outputs and notes must match
        if self.output_commitments.len() != self.output_notes.len() {
            return false;
        }

        // Each commitment must match its note
        for (commitment, note) in self.output_commitments.iter().zip(self.output_notes.iter()) {
            if commitment != &note.commitment() {
                return false;
            }
        }

        true
    }
}

/// Withdraw transaction: Private -> Public
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawTx {
    /// Transaction ID
    pub tx_id: String,

    /// Input nullifier (spending shielded note)
    pub input_nullifier: Nullifier,

    /// Amount being withdrawn
    pub amount: u64,

    /// Public recipient address (on Solana)
    pub to_public: Vec<u8>,

    /// ZK proof (proves ownership of nullifier)
    pub zk_proof: Vec<u8>,

    /// Merkle root at time of transaction
    pub merkle_root: [u8; 32],

    /// Transaction fee
    pub fee: u64,

    /// Timestamp
    pub timestamp: u64,
}

impl WithdrawTx {
    /// Create a new withdraw transaction
    pub fn new(
        input_nullifier: Nullifier,
        amount: u64,
        to_public: Vec<u8>,
        merkle_root: [u8; 32],
        fee: u64,
    ) -> Self {
        let tx_id = uuid::Uuid::new_v4().to_string();

        // A pre-epoch clock must not panic the constructor; fall back to 0.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        WithdrawTx {
            tx_id,
            input_nullifier,
            amount,
            to_public,
            zk_proof: Vec::new(), // Placeholder
            merkle_root,
            fee,
            timestamp,
        }
    }

    /// Verify withdraw transaction
    pub fn verify(&self) -> bool {
        // Zero-amount withdrawals are invalid.
        if self.amount == 0 {
            return false;
        }

        // Amount must cover fee
        if self.amount < self.fee {
            return false;
        }

        // Must have recipient
        if self.to_public.is_empty() {
            return false;
        }

        true
    }
}

/// Transaction status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Pending validation
    Pending,

    /// Being verified by validators
    Verifying,

    /// Verified and accepted
    Accepted,

    /// Rejected (invalid)
    Rejected { reason: String },
}

/// Transaction with status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrackedTransaction {
    /// The transaction
    pub transaction: ShieldedTransaction,

    /// Current status
    pub status: TransactionStatus,

    /// Number of confirmations
    pub confirmations: u32,
}

impl TrackedTransaction {
    /// Create a new tracked transaction
    pub fn new(transaction: ShieldedTransaction) -> Self {
        TrackedTransaction {
            transaction,
            status: TransactionStatus::Pending,
            confirmations: 0,
        }
    }

    /// Mark as verified
    pub fn mark_verified(&mut self) {
        self.status = TransactionStatus::Accepted;
        self.confirmations += 1;
    }

    /// Mark as rejected
    pub fn mark_rejected(&mut self, reason: String) {
        self.status = TransactionStatus::Rejected { reason };
        // A rejected transaction carries no confirmations: leaving a
        // non-zero count intact would report a failed tx as confirmed.
        self.confirmations = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_transaction() {
        let from_public = vec![1u8; 32];
        let recipient = ShieldedAddress([2u8; 32]);
        let randomness = [42u8; 32];

        let tx = DepositTx::new(from_public, 1000, recipient, randomness, 10);

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 10);
        assert_eq!(tx.output_note.amount, 990); // 1000 - 10
        assert!(tx.verify());
    }

    #[test]
    fn test_transfer_transaction() {
        let nullifiers = vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])];

        let note1 = Note::new_native(ShieldedAddress([10u8; 32]), 500, [1u8; 32]);
        let note2 = Note::new_native(ShieldedAddress([20u8; 32]), 490, [2u8; 32]);

        let tx = TransferTx::new(nullifiers, vec![note1, note2], [0u8; 32], 10);

        assert_eq!(tx.input_nullifiers.len(), 2);
        assert_eq!(tx.output_notes.len(), 2);
        assert!(tx.verify_structure());
    }

    #[test]
    fn test_withdraw_transaction() {
        let nullifier = Nullifier([1u8; 32]);
        let to_public = vec![5u8; 32];

        let tx = WithdrawTx::new(nullifier, 1000, to_public, [0u8; 32], 10);

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 10);
        assert!(tx.verify());
    }

    #[test]
    fn test_transaction_id() {
        let tx = ShieldedTransaction::Deposit(DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        ));

        let id = tx.id();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_tracked_transaction() {
        let tx = ShieldedTransaction::Deposit(DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        ));

        let mut tracked = TrackedTransaction::new(tx);
        assert_eq!(tracked.status, TransactionStatus::Pending);
        assert_eq!(tracked.confirmations, 0);

        tracked.mark_verified();
        assert_eq!(tracked.status, TransactionStatus::Accepted);
        assert_eq!(tracked.confirmations, 1);
    }

    #[test]
    fn test_invalid_deposit_fee() {
        let mut tx = DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        );

        // Make fee larger than amount
        tx.fee = 2000;
        assert!(!tx.verify());
    }

    #[test]
    fn test_invalid_transfer_structure() {
        let tx = TransferTx::new(
            vec![], // Empty inputs - invalid
            vec![Note::new_native(ShieldedAddress([1u8; 32]), 100, [1u8; 32])],
            [0u8; 32],
            10,
        );

        assert!(!tx.verify_structure());
    }

    #[test]
    fn test_deposit_fee_exceeding_amount_does_not_panic() {
        // amount < fee used to panic with an integer underflow in
        // `new_asset` (`amount - fee`); it must construct (with a zero-value
        // note) and then fail verification.
        let tx = DepositTx::new(vec![1u8; 32], 5, ShieldedAddress([2u8; 32]), [3u8; 32], 10);
        assert_eq!(tx.output_note.amount, 0);
        assert!(!tx.verify());
    }

    #[test]
    fn test_zero_amount_deposit_and_withdraw_fail_verify() {
        let deposit = DepositTx::new(vec![1u8; 32], 0, ShieldedAddress([2u8; 32]), [3u8; 32], 0);
        assert!(!deposit.verify());

        let withdraw = WithdrawTx::new(Nullifier([1u8; 32]), 0, vec![5u8; 32], [0u8; 32], 0);
        assert!(!withdraw.verify());
    }

    #[test]
    fn test_deposit_with_empty_sender_fails_verify() {
        let tx = DepositTx::new(
            vec![], // Empty from_public - invalid
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        );
        assert!(!tx.verify());
    }

    #[test]
    fn test_transfer_duplicate_nullifier_fails_structure() {
        let tx = TransferTx::new(
            vec![Nullifier([1u8; 32]), Nullifier([1u8; 32])], // Same note twice
            vec![Note::new_native(
                ShieldedAddress([10u8; 32]),
                500,
                [1u8; 32],
            )],
            [0u8; 32],
            10,
        );
        assert!(!tx.verify_structure());
    }

    #[test]
    fn test_transfer_duplicate_commitment_fails_structure() {
        // Two identical notes produce identical commitments: the same note
        // minted twice within one transfer.
        let note = Note::new_native(ShieldedAddress([10u8; 32]), 500, [1u8; 32]);
        let tx = TransferTx::new(
            vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])],
            vec![note.clone(), note],
            [0u8; 32],
            10,
        );
        assert!(!tx.verify_structure());
    }

    #[test]
    fn test_mark_rejected_resets_confirmations() {
        let tx = ShieldedTransaction::Deposit(DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        ));

        let mut tracked = TrackedTransaction::new(tx);
        tracked.mark_verified();
        assert_eq!(tracked.confirmations, 1);

        tracked.mark_rejected("invalid proof".to_string());
        assert_eq!(
            tracked.status,
            TransactionStatus::Rejected {
                reason: "invalid proof".to_string()
            }
        );
        assert_eq!(tracked.confirmations, 0);
    }
}
