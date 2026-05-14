//! Convenience structs for commonly defined fields in claims.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Generic [JWT claims](https://tools.ietf.org/html/rfc7519#page-8) with
/// defined fields for registered and private claims.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    #[serde(flatten)]
    pub private: BTreeMap<String, serde_json::Value>,
}

impl Claims {
    pub fn new(registered: RegisteredClaims) -> Self {
        Claims {
            registered,
            private: BTreeMap::new(),
        }
    }
}

pub type SecondsSinceEpoch = u64;

/// Registered claims according to the
/// [JWT specification](https://tools.ietf.org/html/rfc7519#page-9).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisteredClaims {
    #[serde(rename = "iss")]
    pub issuer: Option<String>,

    #[serde(rename = "sub")]
    pub subject: Option<String>,

    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<StringOrVec>,

    #[serde(rename = "exp")]
    pub expiration: Option<SecondsSinceEpoch>,

    #[serde(rename = "nbf")]
    pub not_before: Option<SecondsSinceEpoch>,

    #[serde(rename = "iat")]
    pub issued_at: Option<SecondsSinceEpoch>,

    #[serde(rename = "jti")]
    pub json_web_token_id: Option<String>,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StringOrVec {
    String(String),
    Vec(Vec<String>),
}

impl StringOrVec {
    pub fn is_string(&self) -> bool {
        matches!(self, StringOrVec::String(_))
    }

    pub fn is_string_and(&self, f: impl FnOnce(&str) -> bool) -> bool {
        matches!(self, StringOrVec::String(s) if f(s))
    }

    pub fn is_vec(&self) -> bool {
        matches!(self, StringOrVec::Vec(_))
    }

    pub fn is_vec_and(&self, f: impl FnOnce(&[String]) -> bool) -> bool {
        matches!(self, StringOrVec::Vec(v) if f(v))
    }
}

impl Default for StringOrVec {
    fn default() -> Self {
        StringOrVec::String(String::new())
    }
}

impl std::fmt::Debug for StringOrVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringOrVec::String(s) => write!(f, "{}", s),
            StringOrVec::Vec(v) => write!(f, "{:?}", v),
        }
    }
}

impl From<String> for StringOrVec {
    fn from(s: String) -> Self {
        StringOrVec::String(s)
    }
}

impl From<Vec<String>> for StringOrVec {
    fn from(v: Vec<String>) -> Self {
        StringOrVec::Vec(v)
    }
}

// /// Struct to handle the `aud` field because the JWT spec says that
// /// it can be either a string or an array of strings.
// /// [Audience Claim Specificatgion](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3).
// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct StringOrVec {
//     one: Option<String>,
//     multi: Option<Vec<String>>,
// }

// struct StringOrVecVisitor;

// impl<'de> Visitor<'de> for StringOrVecVisitor {
//     type Value = StringOrVec;

//     fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//         formatter.write_str("a string or an array of strings")
//     }

//     fn visit_str<E>(self, value: &str) -> Result<StringOrVec, E>
//     where
//         E: Error,
//     {
//         Ok(StringOrVec {
//             one: Some(value.to_string()),
//             multi: None,
//         })
//     }

//     fn visit_seq<S>(self, seq: S) -> Result<StringOrVec, S::Error>
//     where
//         S: SeqAccess<'de>,
//     {
//         match Deserialize::deserialize(value::SeqAccessDeserializer::new(seq)) {
//             Ok(r) => Ok(StringOrVec {
//                 one: None,
//                 multi: Some(r),
//             }),
//             Err(e) => Err(e),
//         }
//     }
// }

// impl<'de> Deserialize<'de> for StringOrVec {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         deserializer.deserialize_any(StringOrVecVisitor)
//     }
// }

// impl Serialize for StringOrVec {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         if let Some(o) = &self.one {
//             serializer.serialize_str(o)
//         } else if let Some(multi) = &self.multi {
//             let mut seq = serializer.serialize_seq(Some(multi.len()))?;
//             for e in multi {
//                 seq.serialize_element(&e)?;
//             }
//             seq.end()
//         } else {
//             serializer.serialize_none()
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use crate::claims::{Claims, StringOrVec};
    use crate::error::Error;
    use crate::{FromBase64, ToBase64};
    use serde_json::Value;
    use std::default::Default;

    // {"iss":"mikkyang.com","exp":1302319100,"custom_claim":true}
    const ENCODED_PAYLOAD: &str =
        "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImN1c3RvbV9jbGFpbSI6dHJ1ZX0K";

    #[test]
    fn registered_claims() -> Result<(), Error> {
        let claims = Claims::from_base64(ENCODED_PAYLOAD)?;

        assert_eq!(claims.registered.issuer.unwrap(), "mikkyang.com");
        assert_eq!(claims.registered.expiration.unwrap(), 1302319100);
        Ok(())
    }

    #[test]
    fn private_claims() -> Result<(), Error> {
        let claims = Claims::from_base64(ENCODED_PAYLOAD)?;

        assert_eq!(claims.private["custom_claim"], Value::Bool(true));
        Ok(())
    }

    #[test]
    fn roundtrip() -> Result<(), Error> {
        let mut claims: Claims = Default::default();
        claims.registered.issuer = Some("mikkyang.com".into());
        claims.registered.expiration = Some(1302319100);
        let enc = claims.to_base64()?;
        assert_eq!(claims, Claims::from_base64(&*enc)?);
        Ok(())
    }

    #[test]
    fn aud_single() -> Result<(), Error> {
        // {"iss": "mikkyang.com", "exp": 1302319100, "custom_claim": true, "aud": "test", "alg": "HS256" }
        let payload = "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImN1c3RvbV9jbGFpbSI6dHJ1ZSwiYXVkIjoidGVzdCIsImFsZyI6IkhTMjU2In0";

        let claims = Claims::from_base64(payload)?;

        assert_ne!(claims.registered.audience, None);

        let aud = &claims.registered.audience.unwrap();

        assert_eq!(aud, &StringOrVec::String("test".to_string()));
        Ok(())
    }

    #[test]
    fn aud_multi() -> Result<(), Error> {
        // {"iss": "mikkyang.com", "exp": 1302319100, "custom_claim": true, "aud": ["test1", "test2"], "alg": "HS256" }
        let payload = "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImN1c3RvbV9jbGFpbSI6dHJ1ZSwiYXVkIjpbInRlc3QxIiwidGVzdDIiXSwiYWxnIjoiSFMyNTYifQ";

        let claims = Claims::from_base64(payload)?;

        assert_ne!(claims.registered.audience, None);

        let aud = &claims.registered.audience.unwrap();

        assert_eq!(
            aud,
            &StringOrVec::Vec(vec!["test1".to_string(), "test2".to_string()])
        );
        Ok(())
    }
}
