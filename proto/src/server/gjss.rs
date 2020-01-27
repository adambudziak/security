use rocket_contrib::json::JsonValue;

use crate::protocols::goh_ss::{self, VerifyParams};

pub fn verify_gjss(params: VerifyParams) -> JsonValue {
    let valid = goh_ss::verify(&params);
    json!({ "valid": valid })
}
