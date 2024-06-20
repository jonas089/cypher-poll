use std::{fs, path::PathBuf};
use pgp::{types::{Mpi, PublicKeyTrait, SecretKeyTrait}, Deserializable, SignedPublicKey, SignedSecretKey};

pub struct GpgSigner{
    pub secret_key_asc_path: Option<PathBuf>,
    pub public_key_asc_path: Option<PathBuf>,

    // initialize with None, call init()
    pub signed_secret_key: Option<SignedSecretKey>,
    pub signed_public_key: Option<SignedPublicKey>
}

impl GpgSigner{
    pub fn init(&mut self){
        // import private key from file
        let secret_key_string: String = fs::read_to_string(&self.secret_key_asc_path.as_ref().expect("Missing secret key path")).expect("Failed to read secret key");
        self.signed_secret_key = Some(SignedSecretKey::from_string(&secret_key_string).unwrap().0);
        // import public key from file
        let public_key_string: String = fs::read_to_string(&self.public_key_asc_path.as_ref().expect("Missing secret key path")).expect("Failed to read public key");
        self.signed_public_key = Some(SignedPublicKey::from_string(&public_key_string).unwrap().0);
    }
    pub fn init_signer(&mut self){
        // import private key from file
        let secret_key_string: String = fs::read_to_string(&self.secret_key_asc_path.as_ref().expect("Missing secret key path")).expect("Failed to read secret key");
        self.signed_secret_key = Some(SignedSecretKey::from_string(&secret_key_string).unwrap().0);
    }
    pub fn init_verifier(&mut self){
        // import public key from file
        let public_key_string: String = fs::read_to_string(&self.public_key_asc_path.as_ref().expect("Missing secret key path")).expect("Failed to read public key");
        self.signed_public_key = Some(SignedPublicKey::from_string(&public_key_string).unwrap().0);
    }
    pub fn sign_bytes(&mut self, data: &[u8]) -> Vec<Mpi>{
        assert!(self.signed_secret_key.is_some());
        self.signed_secret_key.as_ref().unwrap().create_signature(|| "".to_string(), pgp::crypto::hash::HashAlgorithm::MD5, &data).expect("Failed to generate signature")
    }
    pub fn is_valid_signature(&mut self, signature: Vec<Mpi>, data: &[u8]) -> bool{
        assert!(self.signed_public_key.is_some());
        match self.signed_public_key.as_ref().unwrap().verify_signature(pgp::crypto::hash::HashAlgorithm::MD5, &data, &signature){
            Ok(_) => true,
            Err(_) => false
        }
    }
}


#[test]
fn test(){
    let mut signer = GpgSigner{
        secret_key_asc_path: Some(PathBuf::from("/Users/chef/Desktop/cypher-poll/resources/test/key.sec.asc")),
        public_key_asc_path: Some(PathBuf::from("/Users/chef/Desktop/cypher-poll/resources/test/key.asc")),
        signed_secret_key: None,
        signed_public_key: None
    };
    signer.init();
    let data: Vec<u8> = vec![0u8];
    let signature = signer.sign_bytes(&data);
    assert!(signer.is_valid_signature(signature, &data));
}

// to find: gpg --list-keys || gpg --list-secret-keys
// to export: gpg --armor --export KEY_ID > key.asc || --export-secret-keys KEY_ID

// KEY_ID: 51C1249F74553A283A020670FB8E64A4B19D7263