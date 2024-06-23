use methods::VOTING_ELF;
use risc0_types::CircuitInputs;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

pub fn prove_default(inputs: CircuitInputs) -> Receipt {
    let env = ExecutorEnv::builder()
        .write(&inputs)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    prover
        .prove(env, VOTING_ELF)
        .expect("Failed to generate proof")
}

#[cfg(feature = "groth16")]
pub fn prove_groth16(inputs: CircuitInputs) -> Receipt {
    use risc0_groth16::docker::stark_to_snark;
    use risc0_zkvm::{
        get_prover_server, recursion::identity_p254, CompactReceipt, ExecutorEnv, ExecutorImpl,
        InnerReceipt, ProverOpts, Receipt, VerifierContext,
    };

    let env = ExecutorEnv::builder()
        .write(&inputs)
        .unwrap()
        .build()
        .unwrap();
    let mut exec = ExecutorImpl::from_elf(env, VOTING_ELF).unwrap();
    let session = exec.run().unwrap();
    let opts = ProverOpts::default();
    let ctx = VerifierContext::default();
    let prover = get_prover_server(&opts).unwrap();
    let receipt = prover.prove_session(&ctx, &session).unwrap();

    let claim = receipt.get_claim().unwrap();
    let composite_receipt = receipt.inner.composite().unwrap();
    let succinct_receipt = prover.compress(composite_receipt).unwrap();
    let journal = session.journal.unwrap().bytes;

    let ident_receipt = identity_p254(&succinct_receipt).unwrap();
    let seal_bytes = ident_receipt.get_seal_bytes();

    let seal = stark_to_snark(&seal_bytes).unwrap().to_vec();

    Receipt::new(
        InnerReceipt::Compact(CompactReceipt { seal, claim }),
        journal,
    )
}
