use rocket_contrib::json::JsonValue;

use crate::protocols::schnorr;
use crate::protocols::schnorr::VerifyParams;

pub fn verify_sss(params: VerifyParams) -> JsonValue {
    let valid = schnorr::verify_signature(&params);
    json!({ "valid": valid })
}
