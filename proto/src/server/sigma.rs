use crate::protocols::sigma_ake::{
    InitParams, ExchangeInit, ExchangeFinish, create_session, Session,
    compute_mac, sign_commitments, get_session_key
};
use crate::protocols::schnorr::verify_signature;

use rocket::response::status::NotFound;


use rocket_contrib::databases::redis::Commands;
use rocket_contrib::json::{Json, JsonValue};

use crate::server::common::SessionDbConn;
use crate::common::{InitSchemeBody, GenericSchemeBody, GenericResponse};

use mcl::bn::Fr;

use crate::constants::default_g1;

use sha3::{Digest, Sha3_512};


pub fn init_sigma(params: Json<InitSchemeBody<InitParams>>, conn: SessionDbConn) -> JsonValue {
    let params = params.into_inner();
    
    let g1 = default_g1();
    let secret_key = Fr::from_csprng();
    let public_key = &g1 * &secret_key;
    let _server_commitment = Fr::from_csprng();
    let server_commitment = &g1 * _server_commitment;
    let client_commitment = &params.payload.client_commitment;

    let g_xy = client_commitment * &_server_commitment;

    
    let b_mac = compute_mac(&g_xy, &public_key);
    let sig = sign_commitments(
        &secret_key,
        client_commitment,
        &server_commitment);

    let exchange_init = ExchangeInit {
        b_mac: base64::encode(&b_mac),
        server_public_key: public_key,
        server_commitment: server_commitment.clone(),
        sig: sig
    };

    let id = uuid::Uuid::new_v4();

    conn.set::<_, _, ()>(
        id.to_string(),
        serde_json::to_string(&create_session(
            &params.payload,
            &secret_key,
            &g_xy,
        ))
        .unwrap(),
    )
    .unwrap();

    conn.expire::<_, ()>(id.to_string(), 30).unwrap();

    let response = GenericResponse {
        session_token: id.to_string(),
        payload: exchange_init,
    };
    serde_json::to_value(&response).unwrap().into()
}


pub fn exchange_sigma(
    params: Json<GenericSchemeBody<ExchangeFinish>>,
    conn: SessionDbConn,
) -> Result<JsonValue, NotFound<String>> {
    let params = params.into_inner();
    let exchange_finish = params.payload;

    let id = params.session_token;

    let session: String = conn.get(&id).map_err(|_| {
        NotFound(format!("The session for {} doesn't exist or expired", id))
    })?;

    conn.del::<_, ()>(&id).unwrap();
    let session: Session = serde_json::from_str(&session).unwrap();
    
    let g_xy = session.g_xy;
    let expected_mac = compute_mac(&g_xy, &exchange_finish.client_public_key);
    let expected_mac = base64::encode(&expected_mac);

    if expected_mac != exchange_finish.a_mac {
        // return Err(())
    }

    if !verify_signature(&exchange_finish.sig) {
        // return Err(())
    }

    let session_key = get_session_key(&g_xy);
    let hasher = Sha3_512::new()
        .chain(session_key.as_slice())
        .chain(exchange_finish.msg);

    let response = base64::encode(hasher.result().as_slice());

    Ok(json!({"msg": response}))
}