//! Algorithms capable of signing and verifying tokens. By default only the
//! `hmac` crate's `Hmac` type is supported. For more algorithms, enable the
//! feature `openssl` and see the [openssl](openssl/index.html)
//! module. The `none` algorithm is explicitly not supported.
//! ## Examples
//! ```
//! use hmac::{Hmac, Mac};
//! use sha2::Sha256;
//!
//! let hs256_key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
//! ```

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;

#[cfg(feature = "ed25519-dalek")]
pub mod ed25519_dalek;
#[cfg(feature = "openssl")]
pub mod openssl;
pub mod rust_crypto;
pub mod store;

/// The type of an algorithm, corresponding to the
/// [JWA](https://tools.ietf.org/html/rfc7518) specification.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlgorithmType {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
    Es512,
    Ps256,
    Ps384,
    Ps512,
    EdDSA,
    #[serde(rename = "none")]
    None,
}

impl Default for AlgorithmType {
    fn default() -> Self {
        AlgorithmType::Hs256
    }
}

/// The type of a hash algorithm, according to the [IANA
/// Registry](https://www.iana.org/assignments/named-information/named-information.xhtml)
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum HashAlgorithmType {
    #[serde(rename = "sha-256")]
    Sha256,

    #[serde(rename = "sha-384")]
    Sha384,

    #[serde(rename = "sha-512")]
    Sha512,
}

/// Mechanisms for associating a proof-of-possession key with a JWT
#[derive(PartialEq, Serialize, Deserialize)]
pub enum KeyConfirmation {
    #[serde(rename = "jwk")]
    Jwk(Value),

    #[serde(rename = "jkt")]
    JwkThumbprint(String),
}

impl KeyConfirmation {
    pub fn matches(&self, key: &impl KeyConfirmationAlgorithm) -> bool {
        match self {
            KeyConfirmation::Jwk(_) => *self == key.jwk_confirmation(),
            KeyConfirmation::JwkThumbprint(_) => *self == key.jwk_thumbprint_confirmation(),
        }
    }
}

/// An algorithm capable of being used as a ProofOfPossession JWT
pub trait KeyConfirmationAlgorithm {
    fn as_jwk(&self) -> Value;

    fn thumbprint(&self) -> String;

    fn jwk_confirmation(&self) -> KeyConfirmation {
        KeyConfirmation::Jwk(self.as_jwk())
    }

    fn jwk_thumbprint_confirmation(&self) -> KeyConfirmation {
        KeyConfirmation::JwkThumbprint(self.thumbprint())
    }
}

/// An algorithm capable of signing base64 encoded header and claims strings.
/// strings.
pub trait SigningAlgorithm {
    fn algorithm_type(&self) -> AlgorithmType;

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error>;
}

/// An algorithm capable of verifying base64 encoded header and claims strings.
pub trait VerifyingAlgorithm {
    fn algorithm_type(&self) -> AlgorithmType;

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error>;

    fn verify(&self, header: &str, claims: &str, signature: &str) -> Result<bool, Error> {
        use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
        let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(signature)?;
        self.verify_bytes(header, claims, &*signature_bytes)
    }
}

/// A hash algorithm
pub trait HashAlgorithm {
    fn hash_algorithm_type(&self) -> HashAlgorithmType;

    fn hash(&self, data: impl AsRef<[u8]>) -> String;
}

/// Generate random data
pub(crate) fn random_data(len: usize) -> String {
    let mut vec = vec![0; len];
    let mut rng = rand::thread_rng();
    rng.fill(vec.as_mut_slice());
    BASE64_URL_SAFE_NO_PAD.encode(vec)
}

// TODO: investigate if these AsRef impls are necessary
impl<T: AsRef<dyn VerifyingAlgorithm>> VerifyingAlgorithm for T {
    fn algorithm_type(&self) -> AlgorithmType {
        self.as_ref().algorithm_type()
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        self.as_ref().verify_bytes(header, claims, signature)
    }
}

impl<T: AsRef<dyn SigningAlgorithm>> SigningAlgorithm for T {
    fn algorithm_type(&self) -> AlgorithmType {
        self.as_ref().algorithm_type()
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        self.as_ref().sign(header, claims)
    }
}

fn make_body(header: &str, claims: &str) -> Vec<u8> {
    let mut body = vec![];
    body.extend(header.as_bytes());
    body.extend(crate::SEPARATOR.as_bytes());
    body.extend(claims.as_bytes());
    body
}
