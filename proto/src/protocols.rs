use std::fmt::Debug;
use serde::{Serialize, Deserialize};

pub mod schnorr {

    use mcl::bn::{Fr, G1};
    use mcl::traits::Formattable;

    use super::*;

    use crate::{common::*, constants::*};
    use sha3::{Digest, Sha3_256};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InitParams {
        #[serde(with="serde_mcl_default", rename="X")]
        pub commitment: G1,
        #[serde(with="serde_mcl_default", rename="A")]
        pub pubkey: G1,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ProofParams {
        #[serde(with="serde_mcl_default", rename="s")]
        pub proof: Fr,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ChallengeParams {
        #[serde(with="serde_mcl_default", rename="c")]
        pub challenge: Fr,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VerifyParams {
        #[serde(with="serde_mcl_default", rename="s")]
        pub signature: Fr,
        #[serde(with="serde_mcl_default", rename="X")]
        pub commitment: G1,
        #[serde(with="serde_mcl_default", rename="A")]
        pub pubkey: G1,
        #[serde(rename="msg")]
        pub message: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Session {
        #[serde(with="serde_mcl_default")]
        pub challenge: Fr,
        #[serde(with="serde_mcl_default")]
        pub commitment: G1,
        #[serde(with="serde_mcl_default")]
        pub pubkey: G1,
    }

    pub fn init(_params: &InitParams) -> ChallengeParams {
        ChallengeParams { challenge: Fr::from_csprng() }
    }

    pub fn verify(session: &Session, proof: &ProofParams) -> bool {
        let g1 = default_g1();
        let proof = g1 * proof.proof;
        let expected = &session.commitment + &session.pubkey * session.challenge;
        proof == expected
    }

    pub fn create_session(init: &InitParams, challenge: &Fr) -> Session {
        Session {
            commitment: init.commitment.clone(),
            pubkey: init.pubkey.clone(),
            challenge: *challenge
        }
    }

    pub fn sign(priv_key: &Fr, message: String) -> VerifyParams {
        let g1: G1 = default_g1();
        let _commitment = Fr::from_csprng();
        let commitment = &g1 * _commitment;
        println!("{:?}", compute_hash(&commitment, &message).len());
        let challenge: Fr = from_bytes(&compute_hash(&commitment, &message)).unwrap();
        VerifyParams {
            signature: _commitment + priv_key * challenge,
            commitment: commitment,
            pubkey: &g1 * priv_key,
            message: message,
        }
    }

    pub fn verify_signature(params: &VerifyParams) -> bool {
        let challenge: Fr = from_bytes(&compute_hash(&params.commitment, &params.message)).unwrap();
        let generator = default_g1();
        generator * params.signature == &params.commitment + &params.pubkey * challenge
    }

    pub fn compute_hash(commitment: &G1, message: &str) -> Vec<u8> {
        let hasher = Sha3_256::new().chain(message.as_bytes())
              .chain(commitment.get_str(mcl::common::Base::Dec));
        hasher.result().as_slice().to_vec()
    }
}

pub mod okamoto {

    use mcl::bn::Fr;

    use super::*;

    use crate::{common::*, constants::*};

    pub type InitParams = super::schnorr::InitParams;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ProofParams {
        #[serde(with="serde_mcl_default", rename="s1")]
        pub proof1: Fr,
        #[serde(with="serde_mcl_default", rename="s2")]
        pub proof2: Fr,
    }

    pub type ChallengeParams = super::schnorr::ChallengeParams;

    pub type Session = super::schnorr::Session;

    pub fn init(_params: &InitParams) -> ChallengeParams {
        ChallengeParams { challenge: Fr::from_csprng() }
    }

    pub fn verify(session: &Session, proof: &ProofParams) -> bool {
        let g1 = default_g1();
        let g2 = default_g1_2();
        let proof1 = g1 * proof.proof1;
        let proof2 = g2 * proof.proof2;
        let proof = proof1 + proof2;
        let expected = &session.commitment + &session.pubkey * session.challenge;
        proof == expected
    }

    pub fn create_session(init: &InitParams, challenge: &Fr) -> Session {
        Session {
            commitment: init.commitment.clone(),
            pubkey: init.pubkey.clone(),
            challenge: *challenge
        }
    }
}

pub mod mod_schnorr {

    use mcl::bn::{Fr, G1, G2, GT};
    use mcl::traits::RawSerializable;

    use super::*;

    use crate::{common::*, constants::*};
    use sha3::{Digest, Sha3_256};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Session {
        #[serde(with="serde_mcl_default")]
        pub challenge: Fr,
        #[serde(with="serde_mcl_default")]
        pub commitment: G1,
        #[serde(with="serde_mcl_default")]
        pub pubkey: G1,
    }

    pub type InitParams = schnorr::InitParams;
    pub type ChallengeParams = schnorr::ChallengeParams;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ProofParams {
        #[serde(with="serde_mcl_default", rename="s")]
        pub proof: G2,
    }

    pub fn init(_params: &InitParams) -> ChallengeParams {
        ChallengeParams { challenge: Fr::from_csprng() }
    }

    pub fn verify(session: &Session, proof: &ProofParams) -> bool {
        let g1 = default_g1();
        let g_hat = G2::hash_and_map(&compute_hash(&session.commitment, &session.challenge)).unwrap();
        let e1 = GT::from_pairing(&g1, &proof.proof);
        let e2 = GT::from_pairing(&(&session.commitment + &session.pubkey * &session.challenge), &g_hat);
        e1 == e2
    }

    // TODO this hash should be computed differently
    pub fn compute_hash(commitment: &G1, challenge: &Fr) -> Vec<u8> {
        let hasher = Sha3_256::new()
            .chain(commitment.serialize_raw().unwrap())
            .chain(challenge.serialize_raw().unwrap());
        hasher.result().as_slice().to_vec()
    }

    pub fn create_session(init: &InitParams, challenge: &Fr) -> Session {
        Session {
            commitment: init.commitment.clone(),
            pubkey: init.pubkey.clone(),
            challenge: *challenge
        }
    }
}

pub mod bls_ss {

    use mcl::bn::{Fr, G1, G2, GT};
    use mcl::traits::Formattable;

    use super::*;

    use crate::{common::*, constants::*};
    use sha3::{Digest, Sha3_256};


    #[derive(Debug, Serialize, Deserialize)]
    pub struct VerifyParams {
        #[serde(with="serde_mcl_default", rename="s")]
        pub signature: G2,
        #[serde(with="serde_mcl_default", rename="A")]
        pub pubkey: G1,
        #[serde(rename="msg")]
        pub message: String,
    }

    pub fn sign(priv_key: &Fr, message: String) -> VerifyParams {
        let g1 = default_g1();
        let g2 = G2::hash_and_map(message.as_bytes()).unwrap();
        let signature = g2 * priv_key;

        VerifyParams {
            signature: signature,
            pubkey: &g1 * priv_key,
            message: message,
        }
    }

    pub fn verify_signature(params: &VerifyParams) -> bool {
        let g1 = default_g1();
        let g2 = G2::hash_and_map(params.message.as_bytes()).unwrap();
        let e1 = GT::from_pairing(&g1, &params.signature);
        let e2 = GT::from_pairing(&params.pubkey, &g2);
        e1 == e2
    }
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Sis,
    Ois,
    Sss,
    Msis,
    Blsss
}
