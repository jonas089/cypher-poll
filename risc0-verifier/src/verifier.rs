// Verify the receipt, check the journal root_history and add the nullifier to state
use risc0_zkvm::Receipt;
pub fn verify_receipt(receipt: Receipt, root_history: Vec<Vec<u8>>) -> Vec<u8> {
    todo!("verify receipt and check that root is in root_history")
}
