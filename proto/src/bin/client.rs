use anyhow::Result;

use serde_json::json;

use mcl::bn::*;

use proto::constants::*;
use proto::common::*;
use proto::protocols::*;

type InitSchnorr = GenericSchemeBody<schnorr::ChallengeParams>;

async fn init_schnorr(pubkey: &G1, commitment: &G1) -> Result<InitSchnorr> {
    let body = json!({
        "protocol_name": "sis",
        "payload": {
            "pubkey": to_base64(pubkey),
            "commitment": to_base64(commitment),
        }
    });

    let client = reqwest::Client::new();
    let resp = client.post("http://localhost:8000/protocols/sis/init")
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response: InitSchnorr = serde_json::from_str(&resp.text().await?).unwrap();
    Ok(response)
}

fn get_challenge(response: InitSchnorr) -> Fr {
    response.payload.challenge
}

async fn prove_schnorr(id: &uuid::Uuid, proof: &Fr) -> Result<()> {
    let body = serde_json::to_value(
        &GenericSchemeBody {
            protocol_name: Protocol::Sis,
            session_token: id.clone(),
            payload: schnorr::ProofParams {
                proof: proof.clone(),
            }
        }
    ).unwrap();

    let client = reqwest::Client::new();
    let resp = client.post("http://localhost:8000/protocols/sis/verify")
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let resp: std::collections::HashMap<String, bool> = resp.json().await?;

    assert!(resp.get("result").unwrap(), "The verification for SIS failed!");

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
    let token = response.session_token.clone();
    let challenge = get_challenge(response);
    let proof = priv_comm + secret_key * challenge;
    prove_schnorr(&token, &proof).await?;
    Ok(())
}
