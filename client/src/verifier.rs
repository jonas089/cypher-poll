// Verify the receipt, check the journal root_history and add the nullifier to state
use crate::storage::TreeRoot;
use crypto::identity::Nullifier;
use risc0_zkvm::Receipt;

pub fn verify_receipt(receipt: Receipt, root_history: Vec<TreeRoot>) -> Nullifier {
    todo!("verify receipt and check that root is in root_history")
}
