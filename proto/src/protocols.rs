use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub mod schnorr {

    use mcl::bn::{Fr, G1};
    use mcl::traits::Formattable;

    use super::*;

    use crate::{common::*, constants::*};
    use sha3::{Digest, Sha3_256};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InitParams {
        #[serde(with = "serde_mcl_default", rename = "X")]
        pub commitment: G1,
        #[serde(with = "serde_mcl_default", rename = "A")]
        pub pubkey: G1,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ProofParams {
        #[serde(with = "serde_mcl_default", rename = "s")]
        pub proof: Fr,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ChallengeParams {
        #[serde(with = "serde_mcl_default", rename = "c")]
        pub challenge: Fr,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VerifyParams {
        #[serde(with = "serde_mcl_default", rename = "s")]
        pub signature: Fr,
        #[serde(with = "serde_mcl_default", rename = "X")]
        pub commitment: G1,
        #[serde(with = "serde_mcl_default", rename = "A")]
        pub pubkey: G1,
        #[serde(rename = "msg")]
        pub message: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Session {
        #[serde(with = "serde_mcl_default")]
        pub challenge: Fr,
        #[serde(with = "serde_mcl_default")]
        pub commitment: G1,
        #[serde(with = "serde_mcl_default")]
        pub pubkey: G1,
    }

    pub fn init(_params: &InitParams) -> ChallengeParams {
        ChallengeParams {
            challenge: Fr::from_csprng(),
        }
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
            challenge: *challenge,
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
        let hasher = Sha3_256::new()
            .chain(message.as_bytes())
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
        #[serde(with = "serde_mcl_default", rename = "s1")]
        pub proof1: Fr,
        #[serde(with = "serde_mcl_default", rename = "s2")]
        pub proof2: Fr,
    }

    pub type ChallengeParams = super::schnorr::ChallengeParams;

    pub type Session = super::schnorr::Session;

    pub fn init(_params: &InitParams) -> ChallengeParams {
        ChallengeParams {
            challenge: Fr::from_csprng(),
        }
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
            challenge: *challenge,
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
        #[serde(with = "serde_mcl_default")]
        pub challenge: Fr,
        #[serde(with = "serde_mcl_default")]
        pub commitment: G1,
        #[serde(with = "serde_mcl_default")]
        pub pubkey: G1,
    }

    pub type InitParams = schnorr::InitParams;
    pub type ChallengeParams = schnorr::ChallengeParams;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ProofParams {
        #[serde(with = "serde_mcl_default", rename = "s")]
        pub proof: G2,
    }

    pub fn init(_params: &InitParams) -> ChallengeParams {
        ChallengeParams {
            challenge: Fr::from_csprng(),
        }
    }

    pub fn verify(session: &Session, proof: &ProofParams) -> bool {
        let g1 = default_g1();
        let g_hat =
            G2::hash_and_map(&compute_hash(&session.commitment, &session.challenge)).unwrap();
        let e1 = GT::from_pairing(&g1, &proof.proof);
        let e2 = GT::from_pairing(
            &(&session.commitment + &session.pubkey * &session.challenge),
            &g_hat,
        );
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
            challenge: *challenge,
        }
    }
}

pub mod bls_ss {

    use super::*;
    use mcl::bn::{Fr, G1, G2, GT};


    use crate::{common::*, constants::*};
    

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VerifyParams {
        #[serde(with = "serde_mcl_default", rename = "s")]
        pub signature: G2,
        #[serde(with = "serde_mcl_default", rename = "A")]
        pub pubkey: G1,
        #[serde(rename = "msg")]
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

pub mod goh_ss {
    use super::*;
    use mcl::bn::{Fr, G1};
    use sha3::{Digest, Sha3_256};
    use mcl::traits::Formattable;



    use crate::{common::*, constants::*};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Signature {
        #[serde(with = "serde_mcl_default")]
        pub s: Fr,
        #[serde(with = "serde_mcl_default")]
        pub c: Fr,
        #[serde(with = "serde_mcl_default")]
        pub r: Fr,
        #[serde(with = "serde_mcl_default")]
        pub z: G1,
        
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VerifyParams {
        #[serde(rename = "sigma")]
        pub signature: Signature,
        #[serde(with = "serde_mcl_default", rename = "A")]
        pub pubkey: G1,
        #[serde(rename = "msg")]
        pub message: String
    }

    fn get_digest(message: &str, randomness: &Fr) -> Vec<u8> {
        let mut digest = message.as_bytes().to_vec();
        digest.append(&mut randomness.get_str(mcl::common::Base::Dec).as_bytes().to_vec());
        digest
    }

    fn compute_hash(g: &G1, h: &G1, pubkey: &G1, z: &G1, u: &G1, v: &G1) -> Fr {
        let ser = |p: &G1| p.get_str(mcl::common::Base::Dec);
        let hasher = Sha3_256::new()
            .chain(ser(g))
            .chain(ser(h))
            .chain(ser(pubkey))
            .chain(ser(z))
            .chain(ser(u))
            .chain(ser(v));
        from_bytes(hasher.result().as_slice()).unwrap()
    }

    pub fn sign(priv_key: &Fr, message: String) -> VerifyParams {
        let g = default_g1();
        let pubkey = &g * priv_key;
        let r = Fr::from_csprng();
        let h = G1::hash_and_map(&get_digest(&message, &r)).unwrap();
        let z = &h * priv_key;
        let k = Fr::from_csprng();
        let u = &g * k;
        let v = &h * k;
        let c = compute_hash(&g, &h, &pubkey, &z, &u, &v);
        let s = &k + &c * priv_key;
        VerifyParams {
            signature: Signature {
                s, c, r, z
            },
            pubkey,
            message
        }
    }

    pub fn verify(params: &VerifyParams) -> bool {
        let g = default_g1();
        let h = G1::hash_and_map(&get_digest(params.message.as_str(), &params.signature.r)).unwrap();
        let u = &g * params.signature.s + &params.pubkey * params.signature.c.neg();
        let v = &h * params.signature.s + &params.signature.z * params.signature.c.neg();
        let c_prim = compute_hash(&g, &h, &params.pubkey, &params.signature.z, &u, &v);
        params.signature.c == c_prim
    }
}

pub mod sigma_ake {
    use mcl::bn::{Fr, G1};

    use super::*;

    use crate::{common::*, constants::*};
    use crypto::mac::Mac;
    use crypto::poly1305::Poly1305;
    use sha3::{Digest, Sha3_256};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InitParams {
        #[serde(with = "serde_mcl_default", rename = "X")]
        pub client_commitment: G1,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ExchangeInit {
        pub b_mac: String,
        #[serde(with = "serde_mcl_default", rename = "B")]
        pub server_public_key: G1,
        #[serde(with = "serde_mcl_default", rename = "Y")]
        pub server_commitment: G1,
        pub sig: schnorr::VerifyParams,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ExchangeFinish {
        pub a_mac: String,
        #[serde(with = "serde_mcl_default", rename = "A")]
        pub client_public_key: G1,
        pub sig: schnorr::VerifyParams,
        pub msg: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Session {
        #[serde(with = "serde_mcl_default")]
        pub client_commitment: G1,
        #[serde(with = "serde_mcl_default")]
        pub secret_key: Fr,
        #[serde(with = "serde_mcl_default")]
        pub g_xy: G1,
    }

    pub fn create_session(init: &InitParams, secret_key: &Fr, g_xy: &G1) -> Session {
        Session {
            client_commitment: init.client_commitment.clone(),
            secret_key: secret_key.clone(),
            g_xy: g_xy.clone(),
        }
    }

    pub fn finish_exchange(
        secret_key: &Fr,
        client_secret: &Fr,
        exchange_init: ExchangeInit,
        msg: String,
    ) -> ExchangeFinish {
        let g1 = default_g1();
        let public_key = &g1 * secret_key;
        let client_commitment = &g1 * client_secret;
        let g_xy = &exchange_init.server_commitment * client_secret;
        let a_mac = compute_mac(&g_xy, &public_key);
        let sig = sign_commitments(
            secret_key,
            &exchange_init.server_commitment,
            &client_commitment,
        );
        ExchangeFinish {
            a_mac: base64::encode(&a_mac),
            client_public_key: public_key,
            sig,
            msg,
        }
    }

    pub fn get_session_key(g_xy: &G1) -> Vec<u8> {
        let hasher = Sha3_256::new().chain("session_").chain(to_string(g_xy));
        hasher.result().as_slice().to_vec()
    }

    pub fn compute_mac(mac_key_gen: &G1, digest: &G1) -> Vec<u8> {
        let generator_string = to_string(mac_key_gen);
        let hasher = Sha3_256::new().chain("mac_").chain(generator_string);
        let mac_key = hasher.result().as_slice().to_vec();
        let mut mac = Poly1305::new(mac_key.as_slice());
        mac.input(&to_string(digest).as_bytes());
        mac.result().code().to_vec()
    }

    pub fn sign_commitments(
        secret_key: &Fr,
        generator_a: &G1,
        generator_b: &G1,
    ) -> schnorr::VerifyParams {
        let mut message = to_string(generator_a);
        message.push_str(&to_string(generator_b));
        super::schnorr::sign(secret_key, message)
    }
}

pub mod naxos_ake {
    use mcl::bn::{Fr, G1};
    use mcl::traits::Formattable;

    use super::*;

    use crate::{common::*, constants::*};
    use sha3::{Digest, Sha3_256, Sha3_512};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InitRequest {
        #[serde(with = "serde_mcl_default", rename = "X")]
        pub client_commitment: G1,
        #[serde(with = "serde_mcl_default", rename = "A")]
        pub client_pubkey: G1,
        #[serde(rename = "msg")]
        pub message: String
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InitResponse {
        #[serde(with = "serde_mcl_default", rename = "Y")]
        pub server_commitment: G1,
        #[serde(rename = "msg")]
        pub message: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Keys {
        #[serde(with = "serde_mcl_default")]
        pub public_key: G1,
        #[serde(with = "serde_mcl_default")]
        pub secret_key: Fr
    }


    pub fn compute_h1(eph: &Fr, priv_key: &Fr) -> Fr {
        let hasher = Sha3_256::new()
            .chain(to_string(eph))
            .chain(to_string(priv_key));
        from_bytes(hasher.result().as_slice()).unwrap()
    }

    pub fn compute_h2(p1: &G1, p2: &G1, p3: &G1, id_a: &str, id_b: &str) -> Vec<u8> {
        let hasher = Sha3_512::new()
            .chain(to_string(p1))
            .chain(to_string(p2))
            .chain(to_string(p3))
            .chain(id_a)
            .chain(id_b);
        hasher.result().as_slice().to_vec()
    }

    pub fn initiator_compute_key(server_pubkey: &G1, priv_key: &Fr, ephemeral: &Fr, responder_commitment: &G1, id_a: &str, id_b: &str) -> Vec<u8> {
        let h1 = compute_h1(&ephemeral, &priv_key);
        let p1 = responder_commitment * priv_key;
        let p2 = server_pubkey * h1;
        let p3 = responder_commitment * h1;
        compute_h2(&p1, &p2, &p3, id_a, id_b)
    }

    pub fn responder_compute_key(client_pubkey: &G1, priv_key: &Fr, ephemeral: &Fr, initiatior_commitment: &G1, id_a: &str, id_b: &str) -> Vec<u8> {
        let h1 = compute_h1(&ephemeral, &priv_key);
        let p1 = client_pubkey * h1;
        let p2 = initiatior_commitment * priv_key;
        let p3 = initiatior_commitment * h1;
        compute_h2(&p1, &p2, &p3, id_a, id_b)
    }

    pub fn compute_session_key_proof(session_key: &[u8], message: &str) -> String {
        let hasher = Sha3_512::new()
            .chain(session_key)
            .chain(message);

        base64::encode(hasher.result().as_slice())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Sis,
    Ois,
    Msis,
    Sss,
    Blsss,
    Gjss,
    Sigma,
    Naxos
}
