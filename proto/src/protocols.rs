use std::fmt::Debug;
use serde::{Serialize, Deserialize};

pub mod schnorr {

    use mcl::bn::{Fr, G1};

    use super::*;

    use crate::{common::*, constants::*};

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Sis,
    Ois,
}
