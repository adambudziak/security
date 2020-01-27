use anyhow::Result;

use rocket_contrib::databases::redis::Commands;
use rocket_contrib::json::JsonValue;

use crate::common::{GenericResponse, GenericSchemeBody, InitSchemeBody};
use crate::protocols::schnorr;
use crate::server::common::SessionDbConn;

pub fn init_schnorr(
    params: InitSchemeBody<schnorr::InitParams>,
    conn: SessionDbConn,
) -> Result<JsonValue> {
    let id = uuid::Uuid::new_v4();
    let challenge = schnorr::init(&params.payload);

    conn.set::<_, _, ()>(
        id.to_string(),
        serde_json::to_string(&schnorr::create_session(
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
    Ok(serde_json::to_value(&response).unwrap().into())
}

pub fn verify_schnorr(
    params: GenericSchemeBody<schnorr::ProofParams>,
    conn: SessionDbConn,
) -> Result<JsonValue> {
    let id = params.session_token;

    let session: String = conn.get(&id)?;

    conn.del::<_, ()>(&id).unwrap();
    let session: schnorr::Session = serde_json::from_str(&session).unwrap();

    let verified = schnorr::verify(&session, &params.payload);

    Ok(json!({ "verified": verified }))
}
