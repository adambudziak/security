use anyhow::Result;

use mcl::bn::*;

use proto::common::*;
use proto::constants::*;
use proto::protocols::*;

type SchnorrChallenge = GenericResponse<schnorr::ChallengeParams>;

async fn init_schnorr(pubkey: &G1, commitment: &G1) -> Result<SchnorrChallenge> {
    let body = serde_json::to_value(&InitSchemeBody {
        protocol_name: Protocol::Sis,
        payload: schnorr::InitParams {
            pubkey: pubkey.clone(),
            commitment: commitment.clone(),
        },
    })
    .unwrap();
    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/protocols/sis/init", get_server("adam_b")))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response: SchnorrChallenge = serde_json::from_str(&resp.text().await?).unwrap();
    Ok(response)
}

async fn prove_schnorr(session_token: String, proof: Fr) -> Result<()> {
    let body = serde_json::to_value(&GenericSchemeBody {
        protocol_name: Protocol::Sis,
        session_token,
        payload: schnorr::ProofParams { proof },
    })
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/protocols/sis/verify", get_server("adam_b")))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let resp: std::collections::HashMap<String, bool> = resp.json().await?;

    assert!(
        resp.get("verified").unwrap(),
        "The verification for SIS failed!"
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    let g1 = default_g1();

    let secret_key = Fr::from_csprng();
    let public_key = &g1 * secret_key;

    let priv_comm = Fr::from_csprng();
    let commitment = &g1 * priv_comm;
    let response = init_schnorr(&public_key, &commitment).await?;
    let token = response.session_token;
    let challenge = response.payload.challenge;
    let proof = priv_comm + secret_key * challenge;
    prove_schnorr(token, proof).await?;
    Ok(())
}
