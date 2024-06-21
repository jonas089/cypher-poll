// client with commands to create a payload for the server
// must handle two cases:
// 1. generate an identity and submit a signature
// 2. generate a proof payload / receipt

use std::{
    env,
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use clap::{builder::Str, Parser, Subcommand};
use crypto::{
    gpg::GpgSigner,
    identity::{Identity, UniqueIdentity},
};
use pgp::{from_bytes_many, ser::Serialize, types::Mpi};
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
    },
    Vote {
        #[arg(short, long)]
        public_key_path: String,
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

            let mut file = File::create(env::var("NULLIFIER_PATH").unwrap()).unwrap();
            file.write(&identity.nullifier.clone().unwrap()).unwrap();

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
            identity.compute_public_identity(signer.signed_public_key.unwrap());
            // the public identity
            let public_identity: Identity = identity.identity.unwrap();
            let payload: IdentityPayload = IdentityPayload {
                data_serialized,
                signature_serialized,
                public_key_string,
                identity: public_identity,
                username,
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
        }
        // voting requires the exact tree snapshot of the leaf
        Command::Vote { public_key_path } => {
            let snapshot_path: PathBuf = PathBuf::from(env::var("SNAPSHOT_PATH").unwrap());
            let nullifier_path: PathBuf = PathBuf::from(env::var("NULLIFIER_PATH").unwrap());
            let mut snapshot_file = File::open(snapshot_path).unwrap();
            let mut encoded_snapshot: Vec<u8> = Vec::new();
            snapshot_file.read(&mut encoded_snapshot).unwrap();
            let snapshot: VotingTree = serde_json::from_slice(&encoded_snapshot).unwrap();
            let root_history: Vec<Vec<u8>> =
                vec![snapshot.root.clone().expect("Snapshot has no root")];
            let public_key_string: String =
                fs::read_to_string(public_key_path).expect("Failed to read public key");
            let mut nullifier_file = File::open(nullifier_path).unwrap();
            let mut nullifier: Vec<u8> = Vec::new();
            nullifier_file.read(&mut nullifier).unwrap();
            let proof: Receipt = prove_default(CircuitInputs {
                root_history,
                snapshot,
                nullifier,
                public_key_string,
            });
            let payload: Vec<u8> =
                serde_json::to_vec(&proof).expect("Failed to serialize Risc0 receipt");
            // todo: submit payload to server
            let client: Client = Client::new();
            let response = client
                .post("http://127.0.0.1:8080/vote")
                .json(&payload)
                .send()
                .expect("Failed to submit proof");
            assert!(response.status().is_success());
        }
    }
}
