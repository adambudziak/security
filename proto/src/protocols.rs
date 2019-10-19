use std::fmt::Debug;
use serde::{Serialize, Deserialize};

pub mod schnorr {

    use mcl::bn::{Fr, G1};

    use super::*;

    use crate::{common::*, constants::*};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InitParams {
        #[serde(with="serde_base64")]
        pub commitment: G1,
        #[serde(with="serde_base64")]
        pub pubkey: G1,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ProofParams {
        #[serde(with="serde_base64")]
        pub proof: Fr,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ChallengeParams {
        #[serde(with="serde_base64")]
        pub challenge: Fr,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Session {
        #[serde(with="serde_base64")]
        pub challenge: Fr,
        #[serde(with="serde_base64")]
        pub commitment: G1,
        #[serde(with="serde_base64")]
        pub pubkey: G1,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum Stage {
        Init(InitParams),
        Verify(ProofParams),
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
        schnorr::Session {
            commitment: init.commitment.clone(),
            pubkey: init.pubkey.clone(),
            challenge: challenge.clone()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Sis,
}
