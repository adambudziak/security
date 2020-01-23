use anyhow::Result;

use mcl::bn::*;

use proto::common::*;
use proto::constants::*;
use proto::protocols::*;

type SchnorrChallenge = GenericResponse<mod_schnorr::ChallengeParams>;

async fn init_mschnorr(pubkey: &G1, commitment: &G1) -> Result<SchnorrChallenge> {
    let body = serde_json::to_value(&InitSchemeBody {
        protocol_name: Protocol::Msis,
        payload: mod_schnorr::InitParams {
            pubkey: pubkey.clone(),
            commitment: commitment.clone(),
        },
    })
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/protocols/msis/init", get_server("adam_b")))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response = serde_json::from_str(&resp.text().await?).unwrap();
    Ok(response)
}

async fn prove_mschnorr(session_token: String, proof: G2) -> Result<()> {
    let body = serde_json::to_value(&GenericSchemeBody {
        protocol_name: Protocol::Sis,
        session_token,
        payload: mod_schnorr::ProofParams { proof },
    })
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/protocols/msis/verify", get_server("adam_b")))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let resp: std::collections::HashMap<String, bool> = resp.json().await?;

    println!("Verified? {}", resp["verified"]);

    assert!(
        resp.get("verified").unwrap(),
        "The verification for MSIS failed!"
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    let g1 = default_g1();

    let secret_key = Fr::from_csprng();
    let public_key = &g1 * secret_key;

    let _commitment = Fr::from_csprng();
    let commitment = &g1 * _commitment;

    let response = init_mschnorr(&public_key, &commitment).await?;
    let token = response.session_token;
    let challenge = response.payload.challenge;

    let g_hat = G2::hash_and_map(&mod_schnorr::compute_hash(&commitment, &challenge)).unwrap();
    let proof = g_hat * (_commitment + secret_key * challenge);
    prove_mschnorr(token, proof).await?;
    Ok(())
}
