use anyhow::Result;
use std::io::Read;

use rocket::{Request, Data, Outcome::*};
use rocket::data::{FromDataSimple, Outcome};
use rocket::http::{Status};

use std::fs::File;

use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{
    Key,
    Nonce,
    open,
};

const NONCE_LEN: usize = 24;

pub struct SalsaDigest {
    pub message: String
} 

fn get_key() -> Result<Key> {
    let mut buffer = [0_u8; 32];
    let mut key_file = File::open("salsa_key.bin")?;
    key_file.read(&mut buffer)?;
    Ok(Key::from_slice(&buffer).ok_or(std::fmt::Error)?)
}

fn get_nonce(buf: &[u8]) -> Result<Nonce> {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.clone_from_slice(&buf[..NONCE_LEN]);
    Ok(Nonce::from_slice(&nonce).ok_or(std::fmt::Error)?)
}


impl FromDataSimple for SalsaDigest {
    type Error = String;

    fn from_data(req: &Request, data: Data) -> Outcome<Self, Self::Error> {
        // let person_ct = ContentType::new("application", "x-person");
        // if req.content_type() != Some(&person_ct) {
        //     return Outcome::Forward(data);
        // }

        let mut string = String::new();
        if let Err(_) = data.open().read_to_string(&mut string) {
            return Failure((Status::InternalServerError, "Internal error".into()));
        }

        let cipher = base64::decode(&string);
        if let Err(_) = cipher {
            return Failure((Status::UnprocessableEntity, "Bad base64".into()));
        }
        let cipher = cipher.unwrap();
        if cipher.len() <= NONCE_LEN {
            return Failure((Status::UnprocessableEntity, "Invalid data".into()));
        }

        let nonce = get_nonce(&cipher);
        if let Err(_) = nonce {
            return Failure((Status::UnprocessableEntity, "Invalid data".into()));
        }
        let nonce = nonce.unwrap();

        let key = get_key();
        if let Err(_) = key {
            return Failure((Status::InternalServerError, "Internal error".into()));
        }
        let key = key.unwrap();
        
        let message = open(&cipher[NONCE_LEN..], &nonce, &key);
        if let Err(_) = message {
            return Failure((Status::UnprocessableEntity, "Invalid data".into()));
        }
        let message = String::from_utf8(message.unwrap());
        if let Err(_) = message {
            return Failure((Status::UnprocessableEntity, "Invalid data".into()));
        }
        let message = message.unwrap();
        Success(SalsaDigest {
            message
        })
    }
}