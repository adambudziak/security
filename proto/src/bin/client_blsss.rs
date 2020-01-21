use anyhow::Result;

use std::collections::HashMap;
use mcl::bn::*;
use proto::common::*;
use proto::constants::*;
use proto::protocols::{Protocol, bls_ss::{VerifyParams, sign}};

async fn verify_signature(verify_params: VerifyParams) -> Result<bool> {
    let body = serde_json::to_value(&InitSchemeBody {
        protocol_name: Protocol::Blsss,
        payload: verify_params
    })
    .unwrap();
    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/protocols/blsss/verify", get_server("adam_b")))
        .json(&body)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response: HashMap<String, bool> = serde_json::from_str(&resp.text().await?).unwrap();
    println!("{}", response["valid"]);
    Ok(response["valid"])
}

#[tokio::main]
async fn main() -> Result<()> {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    let secret_key = Fr::from_csprng();

    let message = "Hello there!".to_string();
    let verify_params = sign(&secret_key, message);
    verify_signature(verify_params).await?;
    Ok(())
}