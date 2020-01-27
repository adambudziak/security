use anyhow::{ anyhow, Result };

use sodiumoxide::crypto::aead::chacha20poly1305::{
    Key,
    Nonce,
    gen_nonce,
    seal,
    open
};

use std::fs::File;
use std::io::Read;


const NONCE_LEN: usize = 8;

pub struct ChachaMiddleware {
    key: Key,
}

impl ChachaMiddleware {
    
    pub fn new() -> Result<ChachaMiddleware> {
        let mut buffer = [0_u8; 32];
        let mut key_file = File::open("chacha_key.bin")?;
        key_file.read(&mut buffer)?;
    
        let key = Key::from_slice(&buffer).ok_or(std::fmt::Error)?;
        Ok(ChachaMiddleware { key })
    }

    pub fn encrypt(&self, message: &str) -> String {
        let nonce = gen_nonce();
        let mut cipher = seal(message.as_bytes(), None, &nonce, &self.key);
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        nonce_bytes.clone_from_slice(nonce.as_ref());
        let mut digest = Vec::from(&nonce_bytes[..]);
        digest.append(&mut cipher);
        base64::encode(&digest)
    }

    pub fn decrypt(&self, cipher: &str) -> Result<String> {
        let cipher = base64::decode(&cipher)?;
        if cipher.len() <= NONCE_LEN {
            return Err(anyhow!("INVALID_DATA"));
        }
        let nonce = self.get_nonce(&cipher)?;
        let message = open(&cipher[NONCE_LEN..], None, &nonce, &self.key)
            .map_err(|_| anyhow!("INVALID_DATA"))?;
        Ok(String::from_utf8(message)?)
    }


    fn get_nonce(&self, buf: &[u8]) -> Result<Nonce> {
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.clone_from_slice(&buf[..NONCE_LEN]);
        Ok(Nonce::from_slice(&nonce).ok_or(std::fmt::Error)?)
    }
}