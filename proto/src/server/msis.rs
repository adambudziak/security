use rocket::response::status::NotFound;

use rocket_contrib::databases::redis::Commands;
use rocket_contrib::json::{Json, JsonValue};

use crate::common::{GenericResponse, GenericSchemeBody, InitSchemeBody};
use crate::protocols::mod_schnorr;
use crate::server::common::SessionDbConn;

pub fn init_mod_schnorr(
    params: Json<InitSchemeBody<mod_schnorr::InitParams>>,
    conn: SessionDbConn,
) -> JsonValue {
    let params = params.into_inner();
    let id = uuid::Uuid::new_v4();
    let challenge = mod_schnorr::init(&params.payload);

    conn.set::<_, _, ()>(
        id.to_string(),
        serde_json::to_string(&mod_schnorr::create_session(
            &params.payload,
            &challenge.challenge,
        ))
        .unwrap(),
    )
    .unwrap();

    conn.expire::<_, ()>(id.to_string(), 30).unwrap();

    let response = GenericResponse {
        session_token: id.to_string(),
        payload: challenge,
    };
    serde_json::to_value(&response).unwrap().into()
}

pub fn verify_mod_schnorr(
    params: Json<GenericSchemeBody<mod_schnorr::ProofParams>>,
    conn: SessionDbConn,
) -> Result<JsonValue, NotFound<String>> {
    let params = params.into_inner();

    let id = params.session_token;

    let session: String = conn
        .get(&id)
        .map_err(|_| NotFound(format!("The session for {} doesn't exist or expired", id)))?;

    conn.del::<_, ()>(&id).unwrap();
    let session: mod_schnorr::Session = serde_json::from_str(&session).unwrap();

    let verified = mod_schnorr::verify(&session, &params.payload);

    Ok(json!({ "verified": verified }))
}
