use rocket_contrib::json::JsonValue;

use crate::protocols::schnorr::VerifyParams;
use crate::protocols::schnorr;


pub fn verify_sss(params: VerifyParams) -> JsonValue {
    let valid = schnorr::verify_signature(&params);
    json!({ "valid": valid })
}