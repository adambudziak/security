use rocket_contrib::json::JsonValue;

use crate::protocols::bls_ss;
use crate::protocols::bls_ss::VerifyParams;

pub fn verify_blsss(params: VerifyParams) -> JsonValue {
    let valid = bls_ss::verify_signature(&params);
    json!({ "valid": valid })
}
