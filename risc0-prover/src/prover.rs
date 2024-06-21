use methods::VOTING_ELF;
use risc0_types::CircuitInputs;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

pub fn prove_default(inputs: CircuitInputs) -> Receipt{
    let env = ExecutorEnv::builder()
        .write(&inputs)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    prover.prove(env, VOTING_ELF).expect("Failed to generate proof")
}