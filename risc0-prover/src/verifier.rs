use risc0_types::CircuitOutputs;
// Verify the receipt, check the journal root_history and add the nullifier to state
use colored::*;
use methods::VOTING_ID;
use risc0_zkvm::Receipt;

pub fn verify_vote(
    receipt: Receipt,
    root_history: Vec<Vec<u8>>,
    used_nullifiers: Vec<Vec<u8>>,
) -> (String, Vec<u8>) {
    // expect valid proof
    receipt.verify(VOTING_ID).expect("Failed to verify proof");
    // decode journal and verify root_history
    let journal: CircuitOutputs = receipt.journal.decode().expect("Failed to decode journal");
    if used_nullifiers.contains(&journal.nullifier) {
        panic!(
            "{}{}: Duplicate nullifier!",
            "+++++++++ \n".yellow(),
            "Rejected".bold().red()
        )
    }
    for root in journal.root_history {
        if !root_history.contains(&root) {
            panic!(
                "{}{}: Invalid vote!",
                "+++++++++ \n".yellow(),
                "Rejected".bold().red()
            )
        }
    }
    (journal.vote, journal.nullifier)
}
