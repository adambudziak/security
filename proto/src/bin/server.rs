#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;

use rocket_contrib::databases::redis::{self, Commands};
use rocket_contrib::json::{Json, JsonValue};

use proto::common::*;
use proto::protocols::*;

#[database("session_db")]
struct SessionDbConn(redis::Connection);

#[get("/")]
fn index() -> JsonValue {
    json!({
        "sis": "/protocols/sis"
    })
}

#[post("/init", format = "json", data = "<params>")]
fn init_schnorr(
    params: Json<InitSchemeBody<schnorr::InitParams>>,
    conn: SessionDbConn,
) -> JsonValue {
    let params = params.into_inner();
    let id = uuid::Uuid::new_v4();
    let challenge = schnorr::init(&params.payload);

    let _: () = conn.set(
        id.to_string(),
        serde_json::to_string(
            &schnorr::create_session(&params.payload, &challenge.challenge)
        ).unwrap()
    ).unwrap();

    let response = GenericSchemeBody {
        session_token: id,
        protocol_name: Protocol::Sis,
        payload: challenge
    };
    serde_json::to_value(&response).unwrap().into()
}

#[post("/verify", format = "json", data = "<params>")]
fn verify_schnorr(
    params: Json<GenericSchemeBody<schnorr::ProofParams>>,
    conn: SessionDbConn,
) -> JsonValue {

    let params = params.into_inner();

    let session: String = conn.get(params.session_token.to_string()).unwrap();
    let session: schnorr::Session = serde_json::from_str(&session).unwrap();

    let verified = schnorr::verify(&session, &params.payload);

    json!({
        "result": verified
    })
}

fn main() {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    rocket::ignite()
        .mount("/", routes![index])
        .mount("/protocols/sis", routes![init_schnorr, verify_schnorr])
        .attach(SessionDbConn::fairing())
        .launch();
}
