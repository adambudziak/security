use anyhow::Result;

use mcl::bn::*;
use proto::common::*;
use proto::constants::*;
use proto::protocols::{
    sigma_ake::{
        compute_mac, get_session_key, sign_commitments, ExchangeFinish, ExchangeInit, InitParams,
    },
    Protocol,
};

use sha3::{Digest, Sha3_512};

async fn init_exchange(commitment: &G1) -> Result<GenericResponse<ExchangeInit>> {
    let body = serde_json::to_value(&InitSchemeBody {
        protocol_name: Protocol::Sigma,
        payload: InitParams {
            client_commitment: commitment.clone(),
        },
    })
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/protocols/sigma/init", get_server("adam_b")))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response: GenericResponse<ExchangeInit> =
        serde_json::from_str(&resp.text().await?).unwrap();
    Ok(response)
}

fn verify_exchange_init(_init: &ExchangeInit) {}

async fn finalize_exchange(token: String, finish: &ExchangeFinish) -> Result<String> {
    let body = serde_json::to_value(&GenericSchemeBody {
        protocol_name: Protocol::Sigma,
        session_token: token,
        payload: finish,
    })
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(&format!(
            "{}/protocols/sigma/exchange",
            get_server("adam_b")
        ))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response: std::collections::HashMap<String, String> = resp.json().await?;

    Ok(response["msg"].clone())
}

#[tokio::main]
async fn main() -> Result<()> {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    let g1 = default_g1();

    let secret_key = Fr::from_csprng();
    let public_key = &g1 * &secret_key;

    let _commitment = Fr::from_csprng();
    let commitment = &g1 * &_commitment;

    let response = init_exchange(&commitment).await?;
    let token = response.session_token;
    let exchange_init = response.payload;
    verify_exchange_init(&exchange_init);

    let g_xy = &exchange_init.server_commitment * &_commitment;
    let a_mac = base64::encode(&compute_mac(&g_xy, &public_key));
    let sig = sign_commitments(&secret_key, &exchange_init.server_commitment, &commitment);

    let msg = "Hello, there!".to_string();
    let finish = ExchangeFinish {
        a_mac,
        client_public_key: public_key,
        sig,
        msg: msg.clone(),
    };

    let response = finalize_exchange(token, &finish).await?;
    let session_key = get_session_key(&g_xy);
    let hasher = Sha3_512::new().chain(session_key.as_slice()).chain(&msg);

    let expected_message = base64::encode(hasher.result().as_slice());
    println!("{}", response == expected_message);

    Ok(())
}
