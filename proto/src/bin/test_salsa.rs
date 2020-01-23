use std::fs::File;
use std::io::Read;

use anyhow::Result;

use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{
    Key,
    gen_nonce,
    open,
    seal
};

use proto::common::*;
use proto::constants::*;

#[tokio::main]
async fn main() -> Result<()> {
    let mut buffer = [0_u8; 32];
    let mut key_file = File::open("salsa_key.bin")?;
    key_file.read(&mut buffer)?;

    let key = Key::from_slice(&buffer).ok_or(std::fmt::Error)?;
    let nonce = gen_nonce();

    let msg = "Hello, there!";

    let mut cipher = seal(msg.as_bytes(), &nonce, &key);
    let mut nonce_bytes = [0_u8; 24];
    nonce_bytes.clone_from_slice(nonce.as_ref());
    let mut digest = Vec::from(&nonce_bytes[..]);
    digest.append(&mut cipher);
    let digest = base64::encode(&digest);
    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{}/salsa", get_server("adam_b")))
        .body(digest)
        .send()
        .await?;

    resp.error_for_status_ref()?;

    let response = resp.text().await?;
    println!("{}", response);

    Ok(())
}
