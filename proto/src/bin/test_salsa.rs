use anyhow::Result;

use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{gen_key, gen_nonce, open, seal};

fn main() -> Result<()> {
    let key = gen_key();
    let nonce = gen_nonce();

    let msg = "Hello, there!";

    let cipher = seal(msg.as_bytes(), &nonce, &key);
    println!("{:?}", cipher);

    let decrypted = open(cipher.as_slice(), &nonce, &key).map_err(|_| std::fmt::Error)?;
    println!("{}", String::from_utf8(decrypted)?);

    Ok(())
}
