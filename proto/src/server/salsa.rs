use std::io::Read;

use rocket::data::{FromDataSimple, Outcome};
use rocket::http::Status;
use rocket::{Data, Outcome::*, Request};
use serde_json::Value;

use crate::common::salsa::SalsaMiddleware;

pub struct SalsaDigest {
    pub value: Value,
}

impl FromDataSimple for SalsaDigest {
    type Error = String;

    fn from_data(_req: &Request, data: Data) -> Outcome<Self, Self::Error> {
        let salsa = SalsaMiddleware::new();
        if let Err(_) = salsa {
            return Failure((Status::InternalServerError, "INTERNAL_ERROR".into()));
        }
        // let person_ct = ContentType::new("application", "x-person");
        // if req.content_type() != Some(&person_ct) {
        //     return Outcome::Forward(data);
        // }

        let mut cipher = String::new();
        if let Err(_) = data.open().read_to_string(&mut cipher) {
            return Failure((Status::InternalServerError, "INTERNAL_ERROR".into()));
        }
        let message = salsa.unwrap().decrypt(&cipher);
        if let Err(_) = message {
            return Failure((Status::UnprocessableEntity, "INVALID_DATA".into()));
        }
        let value = serde_json::from_str(&message.unwrap());
        if let Err(_) = value {
            return Failure((Status::UnprocessableEntity, "INVALID_DATA".into()));
        };
        let value: Value = value.unwrap();

        Success(SalsaDigest { value })
    }
}
