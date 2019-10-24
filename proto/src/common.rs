use std::fmt::Debug;

use serde::{Serialize, Deserialize};

use mcl::traits::{RawSerializable, Formattable};
use crate::protocols::Protocol;

pub mod serde_base64 {

    use super::*;

    use serde::{
        Deserialize,
        de::{
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
        T: RawSerializable + Default,
    {
        let base64_str: &str = Deserialize::deserialize(deserializer)?;
        from_base64(base64_str).map_err(|_| D::Error::custom("Couldn't deserialize MCL object from base64"))
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

pub mod serde_mcl_default {
    use super::*;

    use serde::{
        de::{
            Deserializer,
            Error as DeError,
        },
        ser::{
            Serializer,
            Error as SerError,
        }
    };

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Formattable + Default,
    {
        let raw_str = Deserialize::deserialize(deserializer)?;
        from_mcl_default(raw_str).map_err(|_| D::Error::custom("Couldn't deserialize from raw string"))
    }

    pub fn serialize<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
    where
        T: Formattable + ?Sized,
        S: Serializer,
        S::Error: SerError
    {
        let serialized = to_mcl_default(t);
        s.serialize_str(&serialized)
    }
}

pub fn to_mcl_default<T: Formattable + ?Sized>(t: &T) -> String {
    t.get_str(mcl::common::Base::Dec)
}

pub fn from_mcl_default<T: Formattable + Default>(raw_str: &str) -> Result<T, ()> {
    let mut result = T::default();
    result.set_str(raw_str, mcl::common::Base::Dec);
    Ok(result)
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

