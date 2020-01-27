use anyhow::Result;

use crate::protocols::naxos_ake::{
    compute_h1, compute_session_key_proof, responder_compute_key, InitRequest, InitResponse, Keys,
};

use rocket_contrib::databases::redis::Commands;
use rocket_contrib::json::JsonValue;

use crate::common::*;
use crate::server::common::SessionDbConn;

use mcl::bn::Fr;

use crate::constants::default_g1;

pub fn init_naxos(init: InitSchemeBody<InitRequest>, conn: SessionDbConn) -> Result<JsonValue> {
    let init = init.payload;
    let keys = get_or_create_naxos_keys(conn);

    let g1 = default_g1();
    let ephemeral = Fr::from_csprng();
    let commitment = &g1 * compute_h1(&ephemeral, &keys.secret_key);

    let session_key = responder_compute_key(
        &init.client_pubkey,
        &keys.secret_key,
        &ephemeral,
        &init.client_commitment,
        to_string(&init.client_pubkey).as_str(),
        to_string(&keys.public_key).as_str(),
    );
    let message = compute_session_key_proof(&session_key, &init.message);

    let response = InitResponse {
        server_commitment: commitment,
        message,
    };

    Ok(serde_json::to_value(&response).unwrap().into())
}

pub fn get_or_create_naxos_keys(conn: SessionDbConn) -> Keys {
    let keys: Result<String, _> = conn.get("naxos_keys");
    match keys {
        Ok(keys) => serde_json::from_str(&keys).unwrap(),
        Err(_) => {
            let g1 = default_g1();
            let secret_key = Fr::from_csprng();
            let public_key = g1 * secret_key;
            let keys = Keys {
                secret_key,
                public_key,
            };
            conn.set::<_, _, ()>("naxos_keys", serde_json::to_string(&keys).unwrap())
                .unwrap();
            keys
        }
    }
}
