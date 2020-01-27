use anyhow::Result;

use mcl::bn::*;
use proto::common::*;
use proto::constants::*;
use proto::protocols::{
    naxos_ake::{InitRequest, InitResponse, initiator_compute_key, compute_session_key_proof, compute_h1},
    Protocol,
};


async fn get_public_key() -> Result<G1> {
    let client = reqwest::Client::new();
    let resp = client
        .get(&format!("{}/protocols/naxos/pkey", get_server("adam_b")))
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response = resp.text().await?;
    Ok(from_base64(&response).unwrap())
}

async fn init_naxos(init: InitRequest) -> Result<InitResponse> {
    let body = serde_json::to_value(&InitSchemeBody {
        protocol_name: Protocol::Naxos,
        payload: init,
    })
    .unwrap();
    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/protocols/naxos/exchange", get_server("adam_b")))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response: InitResponse = serde_json::from_str(&resp.text().await?).unwrap();
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    let g1 = default_g1();
    let secret_key = Fr::from_csprng();
    let pubkey = &g1 * secret_key;
    let ephemeral = Fr::from_csprng();
    let commitment = &g1 * compute_h1(&ephemeral, &secret_key);
    let server_pubkey = get_public_key().await?;

    let message = "Hello there!".to_string();
    let request = InitRequest {
        client_commitment: commitment,
        client_pubkey: pubkey.clone(),
        message: message.clone(),
    };
    let response = init_naxos(request).await?;
    let session_key = initiator_compute_key(&server_pubkey, &secret_key, &ephemeral, &response.server_commitment, to_string(&pubkey).as_str(), to_string(&server_pubkey).as_str());

    println!("{}", response.message == compute_session_key_proof(&session_key, &message));

    Ok(())
}
