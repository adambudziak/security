#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

use rocket::response::status::NotFound;
use anyhow::{ Result, anyhow };

use rocket_contrib::json::{Json, JsonValue};

use proto::common::*;
use proto::protocols::*;

use proto::server::common::SessionDbConn;
use proto::server::{blsss, msis, ois, sigma, sis, sss};
use proto::server::salsa::SalsaDigest;
use proto::common::salsa::SalsaMiddleware;


#[get("/protocols")]
fn index() -> JsonValue {
    json!(["sis", "ois", "sss", "msis"])
}

#[post("/init", format = "json", data = "<params>")]
fn init_schnorr(
    params: Json<InitSchemeBody<schnorr::InitParams>>,
    conn: SessionDbConn,
) -> Result<JsonValue> {
    sis::init_schnorr(params.into_inner(), conn)
}

#[post("/verify", format = "json", data = "<params>")]
pub fn verify_schnorr(
    params: Json<GenericSchemeBody<schnorr::ProofParams>>,
    conn: SessionDbConn,
) -> Result<JsonValue> {
    sis::verify_schnorr(params.into_inner(), conn)
}

#[post("/init", format = "json", data = "<params>")]
pub fn init_okamoto(
    params: Json<InitSchemeBody<okamoto::InitParams>>,
    conn: SessionDbConn,
) -> JsonValue {
    ois::init_okamoto(params, conn)
}

#[post("/verify", format = "json", data = "<params>")]
pub fn verify_okamoto(
    params: Json<GenericSchemeBody<okamoto::ProofParams>>,
    conn: SessionDbConn,
) -> Result<JsonValue, NotFound<String>> {
    ois::verify_okamoto(params, conn)
}

#[post("/verify", format = "json", data = "<params>")]
pub fn verify_sss(params: Json<InitSchemeBody<schnorr::VerifyParams>>) -> JsonValue {
    sss::verify_sss(params.into_inner().payload)
}

#[post("/init", format = "json", data = "<params>")]
fn init_mod_schnorr(
    params: Json<InitSchemeBody<mod_schnorr::InitParams>>,
    conn: SessionDbConn,
) -> JsonValue {
    msis::init_mod_schnorr(params, conn)
}

#[post("/verify", format = "json", data = "<params>")]
pub fn verify_mod_schnorr(
    params: Json<GenericSchemeBody<mod_schnorr::ProofParams>>,
    conn: SessionDbConn,
) -> Result<JsonValue, NotFound<String>> {
    msis::verify_mod_schnorr(params, conn)
}

#[post("/verify", format = "json", data = "<params>")]
pub fn verify_blsss(params: Json<InitSchemeBody<bls_ss::VerifyParams>>) -> JsonValue {
    blsss::verify_blsss(params.into_inner().payload)
}

#[post("/init", format = "json", data = "<params>")]
fn init_sigma(
    params: Json<InitSchemeBody<sigma_ake::InitParams>>,
    conn: SessionDbConn,
) -> JsonValue {
    sigma::init_sigma(params, conn)
}

#[post("/exchange", format = "json", data = "<params>")]
fn exchange_sigma(
    params: Json<GenericSchemeBody<sigma_ake::ExchangeFinish>>,
    conn: SessionDbConn,
) -> Result<JsonValue, NotFound<String>> {
    sigma::exchange_sigma(params, conn)
}


#[post("/salsa/protocols/<protocol>/<stage>", data = "<salsa_digest>")]
fn salsa_encrypted_endpoint(
    protocol: String,
    stage: String,
    salsa_digest: SalsaDigest,
    conn: SessionDbConn,
) -> Result<String> {
    match protocol.as_str() {
        "sis" => match stage.as_str() {
            "init" => sis::init_schnorr(serde_json::from_value(salsa_digest.value)?, conn),
            "verify" => sis::verify_schnorr(serde_json::from_value(salsa_digest.value)?, conn),
            _ => Err(anyhow!("Not found"))
        },
        _ => Err(anyhow!("Not found!"))
    }.map(|value| {
        let digest = serde_json::to_string(&value).unwrap();
        let salsa = SalsaMiddleware::new().unwrap();
        salsa.encrypt(&digest)
    })
}

fn main() {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    rocket::ignite()
        .mount("/", routes![index, salsa_encrypted_endpoint])
        .mount("/protocols/sis", routes![init_schnorr, verify_schnorr])
        .mount("/protocols/ois", routes![init_okamoto, verify_okamoto])
        .mount("/protocols/sss", routes![verify_sss])
        .mount(
            "/protocols/msis",
            routes![init_mod_schnorr, verify_mod_schnorr],
        )
        .mount("/protocols/blsss", routes![verify_blsss])
        .mount("/protocols/sigma", routes![init_sigma, exchange_sigma])
        .attach(SessionDbConn::fairing())
        .launch();
}
