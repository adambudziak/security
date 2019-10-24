use anyhow::Result;

use serde_json::json;

use mcl::bn::*;

use proto::constants::*;
use proto::common::*;
use proto::protocols::*;

type InitSchnorr = GenericSchemeBody<okamoto::ChallengeParams>;

async fn init_okamoto(pubkey: &G1, commitment: &G1) -> Result<InitSchnorr> {
    let body = serde_json::to_value(
        &InitSchemeBody {
            protocol_name: Protocol::Ois,
            payload: okamoto::InitParams {
                pubkey: pubkey.clone(),
                commitment: commitment.clone()
            }
        }
    ).unwrap();

    let client = reqwest::Client::new();
    let resp = client.post("http://localhost:8000/protocols/ois/init")
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

async fn prove_okamoto(id: &uuid::Uuid, proof1: &Fr, proof2: &Fr) -> Result<()> {
    let body = serde_json::to_value(
        &GenericSchemeBody {
            protocol_name: Protocol::Ois,
            session_token: id.clone(),
            payload: okamoto::ProofParams {
                proof1: proof1.clone(),
                proof2: proof2.clone(),
            }
        }
    ).unwrap();

    let client = reqwest::Client::new();
    let resp = client.post("http://localhost:8000/protocols/ois/verify")
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let resp: std::collections::HashMap<String, bool> = resp.json().await?;

    assert!(resp.get("verified").unwrap(), "The verification for OIS failed!");

    Ok(())
}


#[tokio::main]
async fn main() -> Result<()> {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    let g1 = default_g1();
    let g2 = default_g1_2();

    let secret_key1 = Fr::from_csprng();
    let secret_key2 = Fr::from_csprng();
    let public_key = &g1 * secret_key1 + &g2 * &secret_key2;

    let priv_comm1 = Fr::from_csprng();
    let priv_comm2 = Fr::from_csprng();
    let commitment = &g1 * priv_comm1 + &g2 * priv_comm2;
    
    let response = init_okamoto(&public_key, &commitment).await?;
    let token = response.session_token.clone();
    let challenge = get_challenge(response);
    let proof1 = priv_comm1 + secret_key1 * &challenge;
    let proof2 = priv_comm2 + secret_key2 * &challenge;
    prove_okamoto(&token, &proof1, &proof2).await?;
    Ok(())
}
