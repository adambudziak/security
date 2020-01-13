#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

use rocket::response::status::NotFound;

use rocket_contrib::json::{Json, JsonValue};

use proto::common::*;
use proto::protocols::*;

use proto::server::{sis, ois};
use proto::server::common::SessionDbConn;

#[get("/protocols")]
fn index() -> JsonValue {
    json!(["sis", "ois"])
}


#[post("/init", format = "json", data = "<params>")]
fn init_schnorr(
    params: Json<InitSchemeBody<schnorr::InitParams>>,
    conn: SessionDbConn,
) -> JsonValue {
    sis::init_schnorr(params, conn)
}

#[post("/verify", format = "json", data = "<params>")]
pub fn verify_schnorr(
    params: Json<GenericSchemeBody<schnorr::ProofParams>>,
    conn: SessionDbConn,
) -> Result<JsonValue, NotFound<String>> {
    sis::verify_schnorr(params, conn)
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


fn main() {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    rocket::ignite()
        .mount("/", routes![index])
        .mount("/protocols/sis", routes![init_schnorr, verify_schnorr])
        .mount("/protocols/ois", routes![init_okamoto, verify_okamoto])
        .attach(SessionDbConn::fairing())
        .launch();
}
