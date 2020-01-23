use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::protocols::Protocol;
use mcl::traits::{Formattable, RawSerializable};

pub mod serde_base64 {

    use super::*;

    use serde::{
        de::{Deserializer, Error},
        ser::{Error as SerError, Serializer},
        Deserialize,
    };

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: RawSerializable + Default,
    {
        let base64_str: &str = Deserialize::deserialize(deserializer)?;
        from_base64(base64_str)
            .map_err(|_| D::Error::custom("Couldn't deserialize MCL object from base64"))
    }

    pub fn serialize<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
    where
        T: RawSerializable + ?Sized,
        S: Serializer,
        S::Error: SerError,
    {
        let bytes = t
            .serialize_raw()
            .map_err(|_| S::Error::custom("Couldn't serialize?"))?;
        let base64_str = base64::encode(&bytes);
        s.serialize_str(&base64_str)
    }
}

pub mod serde_mcl_default {
    use super::*;

    use serde::{
        de::{Deserializer, Error as DeError},
        ser::{Error as SerError, Serializer},
    };

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Formattable + Default,
    {
        let mut raw_str: String = Deserialize::deserialize(deserializer)?;
        if raw_str.contains(' ') {
            raw_str = "1 ".to_string() + &raw_str.clone();
        }
        from_mcl_default(&raw_str)
            .map_err(|_| D::Error::custom("Couldn't deserialize from raw string"))
    }

    pub fn serialize<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
    where
        T: Formattable + ?Sized,
        S: Serializer,
        S::Error: SerError,
    {
        let serialized = to_mcl_default(t);
        if &serialized[..2] == "1 " {
            s.serialize_str(&serialized[2..])
        } else {
            s.serialize_str(&serialized)
        }
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

pub fn from_bytes<T: RawSerializable + Default>(bytes: &[u8]) -> Result<T, ()> {
    let mut result = T::default();
    let _num_bytes = result.deserialize_raw(bytes);
    // TODO possibly a bug in the rust mcl wrapper (returns 0 even though deserialization was successful)
    // if num_bytes.is_err() {
    //     eprintln!("Deserialization of the value went wrong!");
    //     return Err(());
    // }
    Ok(result)
}

pub fn to_string<T: Formattable>(t: &T) -> String {
    let mut t_string = t.get_str(mcl::common::Base::Dec);
    if &t_string[..2] == "1 " {
        t_string = t_string[2..].to_string();
    }
    t_string
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenericSchemeBody<T>
where
    T: Debug,
{
    pub protocol_name: Protocol,
    pub session_token: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct GenericResponse<T>
where
    T: Debug,
{
    pub session_token: String,
    pub payload: T,
}
