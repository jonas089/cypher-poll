// client with commands to create a payload for the server
// must handle two cases:
// 1. generate an identity and submit a signature
// 2. generate a proof payload / receipt

use std::{
    env,
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

use clap::{Parser, Subcommand};
use crypto::{
    gpg::GpgSigner,
    identity::{Identity, Nullifier, UniqueIdentity},
};
use pgp::types::Mpi;
use reqwest::blocking::Client;
use risc0_prover::prover::prove_default;
use risc0_types::CircuitInputs;
use risc0_zkvm::Receipt;
use serde_json;
use types::IdentityPayload;
use voting_tree::VotingTree;
pub mod types;

#[derive(Parser)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Register {
        #[arg(short, long)]
        data: String,
        #[arg(long)]
        public_key_path: String,
        #[arg(long)]
        private_key_path: String,
        #[arg(short, long)]
        random_seed: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        vote: String
    },
    Vote {
        #[arg(short, long)]
        public_key_path: String,
        #[arg(short, long)]
        vote: String
    },
}

pub fn run(cli: Cli) {
    match cli.command {
        // data corresponds to a unique challenge for the session,
        // should be something like H(P, NonceUser, NonceServer)
        Command::Register {
            data,
            public_key_path,
            private_key_path,
            username,
            random_seed,
            vote
        } => {
            // construct the serialized registration payload
            let public_key_string: String =
                fs::read_to_string(public_key_path).expect("Failed to read public key");
            let data_serialized: Vec<u8> = data.as_bytes().to_vec();
            let mut identity: UniqueIdentity = UniqueIdentity {
                identity: None,
                nullifier: None,
            };
            identity.generate_nullifier(random_seed);

            let mut nullifier_file = File::create(env::var("NULLIFIER_PATH").unwrap()).unwrap();
            nullifier_file
                .write(&serde_json::to_vec(&identity.nullifier.clone().unwrap()).unwrap())
                .unwrap();

            let mut signer = GpgSigner {
                secret_key_asc_path: Some(PathBuf::from(private_key_path)),
                public_key_asc_string: Some(public_key_string.clone()),
                signed_secret_key: None,
                signed_public_key: None,
            };
            signer.init();
            let signature: Vec<Mpi> = signer.sign_bytes(&data_serialized);
            let mut signature_serialized: Vec<Vec<u8>> = Vec::new();
            for mpi in &signature {
                signature_serialized.push(mpi.as_bytes().to_vec())
            }

            let mut signature_deserialized: Vec<Mpi> = Vec::new();
            for series in &signature_serialized {
                signature_deserialized.push(Mpi::from_slice(series))
            }
            assert_eq!(&signature, &signature_deserialized);
            identity.compute_public_identity(signer.signed_public_key.unwrap(), vote);
            // the public identity
            let public_identity: Identity = identity.identity.unwrap();
            let payload: IdentityPayload = IdentityPayload {
                data_serialized,
                signature_serialized,
                public_key_string,
                identity: public_identity,
                username
            };
            // todo: submit payload to server
            // should return a tree snapshot
            // should store that tree snapshot in the
            // designated file
            let client: Client = Client::new();
            let response = client
                .post("http://127.0.0.1:8080/register")
                .json(&payload)
                .send()
                .expect("Failed to register");
            assert!(response.status().is_success());
            let mut snapshot_file = File::create(env::var("SNAPSHOT_PATH").unwrap()).unwrap();
            snapshot_file.write(&response.bytes().unwrap()).unwrap();
        }
        // voting requires the exact tree snapshot of the leaf
        Command::Vote { public_key_path, vote } => {
            let snapshot_path: PathBuf = PathBuf::from(env::var("SNAPSHOT_PATH").unwrap());
            let nullifier_path: PathBuf = PathBuf::from(env::var("NULLIFIER_PATH").unwrap());
            let mut snapshot_file = File::open(snapshot_path).unwrap();
            let mut snapshot_json = String::new();
            snapshot_file.read_to_string(&mut snapshot_json).unwrap();
            let snapshot: VotingTree = serde_json::from_str(&snapshot_json).unwrap();
            let root_history: Vec<Vec<u8>> =
                vec![snapshot.root.clone().expect("Snapshot has no root")];
            let public_key_string: String =
                fs::read_to_string(public_key_path).expect("Failed to read public key");
            let mut nullifier_file = File::open(nullifier_path).unwrap();
            let mut nullifier_json = String::new();
            nullifier_file.read_to_string(&mut nullifier_json).unwrap();
            let nullifier: Nullifier = serde_json::from_str(&mut nullifier_json).unwrap();
            let proof: Receipt = prove_default(CircuitInputs {
                root_history,
                snapshot,
                nullifier,
                vote,
                public_key_string,
            });
            // todo: submit payload to server
            let client = Client::builder()
                .timeout(Duration::from_secs(600))
                .build()
                .expect("Failed to create client");
            let response = client
                .post("http://127.0.0.1:8080/vote")
                .json(&proof)
                .send()
                .expect("Failed to submit proof");
            if !response.status().is_success() {
                println!("Error: Response Status {}", &response.status())
            }
        }
    }
}
