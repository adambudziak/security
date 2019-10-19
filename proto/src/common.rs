use std::fmt::Debug;

use serde::{Serialize, Deserialize};

use mcl::traits::RawSerializable;
use crate::protocols::Protocol;

pub mod serde_base64 {

    use super::*;

    use serde::{
        Deserialize,
        de::{
            value::BorrowedBytesDeserializer,
            DeserializeOwned,
            Deserializer,
            Error,
        },
        ser::{
            Serializer,
            Error as SerError
        }
    };

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned,
    {
        let base64_str: &str = Deserialize::deserialize(deserializer)?;
        let bytes = base64::decode(base64_str).map_err(D::Error::custom)?;
        T::deserialize(BorrowedBytesDeserializer::<D::Error>::new(&bytes))
    }


    pub fn serialize<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
    where
        T: RawSerializable + ?Sized,
        S: Serializer,
        S::Error: SerError,
    {
        let bytes = t.serialize_raw().map_err(|_| S::Error::custom("Couldn't serialize?"))?;
        let base64_str = base64::encode(&bytes);
        s.serialize_str(&base64_str)
    }

}

pub fn from_base64<T: RawSerializable + Default>(base64_str: &str) -> Result<T, ()> {
    let bytes = base64::decode(base64_str).map_err(|_| ())?;
    let mut result = T::default();
    result.deserialize_raw(&bytes)?;
    Ok(result)
}

pub fn to_base64<T: RawSerializable + ?Sized>(t: &T) -> String {
    base64::encode(&t.serialize_raw().unwrap())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenericSchemeBody<T>
where
    T: Debug,
{
    pub protocol_name: Protocol,
    pub session_token: uuid::Uuid,
    pub payload: T,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct InitSchemeBody<T>
where
    T: Debug,
{
    pub protocol_name: Protocol,
    pub payload: T,
}

