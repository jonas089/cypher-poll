#![no_main]
use risc0_zkvm::guest::env;
use risc0_types::{CircuitInputs, CircuitOutputs};
use zk_associated::prover::logic::prover_logic;
risc0_zkvm::guest::entry!(main);


fn main() {
    let mut input: CircuitInputs = env::read();
    env::commit(&prover_logic(&mut input));
}
