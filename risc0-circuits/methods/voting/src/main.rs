#![no_main]
use risc0_zkvm::guest::env;
use risc0_types::{CircuitInputs, CircuitOutputs};
use client::prover::logic::prover_logic;
risc0_zkvm::guest::entry!(main);


fn main() {
    let input: CircuitInputs = env::read();
    
    env::commit(&input);
}
