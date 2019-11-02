#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

use rocket::response::status::NotFound;

use rocket_contrib::databases::redis::{self, Commands};
use rocket_contrib::json::{Json, JsonValue};

use proto::common::*;
use proto::protocols::*;

#[database("session_db")]
struct SessionDbConn(redis::Connection);

#[get("/protocols")]
fn index() -> JsonValue {
    json!(["sis", "ois"])
}

macro_rules! generate_is3_endpoint {
    ($module: ident, $init_module: ident, $verify_module: ident) => {
        #[post("/init", format = "json", data = "<params>")]
        fn $init_module(
            params: Json<InitSchemeBody<$module::InitParams>>,
            conn: SessionDbConn,
        ) -> JsonValue {
            let params = params.into_inner();
            let id = uuid::Uuid::new_v4();
            let challenge = $module::init(&params.payload);

            conn.set::<_, _, ()>(
                id.to_string(),
                serde_json::to_string(&$module::create_session(
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

        #[post("/verify", format = "json", data = "<params>")]
        fn $verify_module(
            params: Json<GenericSchemeBody<$module::ProofParams>>,
            conn: SessionDbConn,
        ) -> Result<JsonValue, NotFound<String>> {
            let params = params.into_inner();

            let id = params.session_token;

            let session: String = conn.get(&id).map_err(|_| {
                NotFound(format!("The session for {} doesn't exist or expired", id))
            })?;

            conn.del::<_, ()>(&id).unwrap();
            let session: $module::Session = serde_json::from_str(&session).unwrap();

            let verified = $module::verify(&session, &params.payload);

            Ok(json!({ "verified": verified }))
        }
    };
}

generate_is3_endpoint![schnorr, init_schnorr, verify_schnorr];
generate_is3_endpoint![okamoto, init_okamoto, verify_okamoto];

fn main() {
    mcl::init::init_curve(mcl::init::Curve::Bls12_381);

    rocket::ignite()
        .mount("/", routes![index])
        .mount("/protocols/sis", routes![init_schnorr, verify_schnorr])
        .mount("/protocols/ois", routes![init_okamoto, verify_okamoto])
        .attach(SessionDbConn::fairing())
        .launch();
}
