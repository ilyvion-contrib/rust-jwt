//! OpenSSL support through the openssl crate.
//! Note that private keys can only be used for signing and that public keys
//! can only be used for verification.
//! ## Examples
//! ```
//! use jwt::PKeyWithDigest;
//! use openssl::hash::MessageDigest;
//! use openssl::pkey::PKey;
//! let pem = include_bytes!("../../test/rs256-public.pem");
//! let rs256_public_key = PKeyWithDigest {
//!     digest: MessageDigest::sha256(),
//!     key: PKey::public_key_from_pem(pem).unwrap(),
//! };
//! ```

use crate::algorithm::{
    AlgorithmType, HashAlgorithm, HashAlgorithmType, KeyConfirmationAlgorithm, SigningAlgorithm,
    VerifyingAlgorithm,
};
use crate::error::Error;
use crate::{ToBase64, SEPARATOR};

use std::collections::HashMap;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasParams, HasPublic, Id, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};

use serde_json::Value;

fn to_curve_name(alg_type: AlgorithmType) -> &'static str {
    match alg_type {
        AlgorithmType::Es256 => "P256",
        AlgorithmType::Es384 => "P384",
        AlgorithmType::Es512 => "P521",
        _ => panic!("Invalid algorithm type"),
    }
}

/// A wrapper class around [PKey](../../../openssl/pkey/struct.PKey.html) that
/// associates the key with a
/// [MessageDigest](../../../openssl/hash/struct.MessageDigest.html).
#[derive(Clone)]
pub struct PKeyWithDigest<T> {
    pub digest: MessageDigest,
    pub key: PKey<T>,
}

impl<T> PKeyWithDigest<T> {
    fn algorithm_type(&self) -> AlgorithmType {
        match (self.key.id(), self.digest.type_()) {
            (Id::RSA, Nid::SHA256) => AlgorithmType::Rs256,
            (Id::RSA, Nid::SHA384) => AlgorithmType::Rs384,
            (Id::RSA, Nid::SHA512) => AlgorithmType::Rs512,
            (Id::EC, Nid::SHA256) => AlgorithmType::Es256,
            (Id::EC, Nid::SHA384) => AlgorithmType::Es384,
            (Id::EC, Nid::SHA512) => AlgorithmType::Es512,
            (Id::ED25519, Nid::UNDEF) => AlgorithmType::EdDSA,
            (Id::ED448, Nid::UNDEF) => AlgorithmType::EdDSA,
            _ => panic!("Invalid algorithm type"),
        }
    }
}

impl<T> PKeyWithDigest<T>
where
    T: HasParams + HasPublic,
{
    fn as_ec_jwk_parts(&self) -> (&'static str, String, String) {
        let ec = self.key.ec_key().unwrap();
        let group = ec.group();
        let pubkey = ec.public_key();

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        pubkey
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .unwrap();

        let crv = to_curve_name(self.algorithm_type());

        let x = x.to_vec();
        let x: String = x.to_base64().unwrap().into();

        let y = y.to_vec();
        let y: String = y.to_base64().unwrap().into();

        (crv, x, y)
    }

    fn as_rsa_jwk_parts(&self) -> (String, String) {
        let rsa = self.key.rsa().unwrap();
        let n = rsa.n().to_vec();
        let e = rsa.e().to_vec();

        (n.to_base64().unwrap().into(), e.to_base64().unwrap().into())
    }
}

impl<T> KeyConfirmationAlgorithm for PKeyWithDigest<T>
where
    T: HasParams + HasPublic,
{
    fn as_jwk(&self) -> Value {
        const JWK_KEY_KTY: &str = "kty";
        const JWK_KTY_RSA: &str = "RSA";
        const JWK_KTY_EC: &str = "EC";
        const JWK_KEY_N: &str = "n";
        const JWK_KEY_E: &str = "e";
        const JWK_KEY_CRV: &str = "crv";
        const JWK_KEY_X: &str = "x";
        const JWK_KEY_Y: &str = "y";

        let raw: HashMap<String, String> = match self.key.id() {
            Id::RSA => {
                let (n, e) = self.as_rsa_jwk_parts();
                HashMap::from([
                    (JWK_KEY_KTY.into(), JWK_KTY_RSA.into()),
                    (JWK_KEY_N.into(), n),
                    (JWK_KEY_E.into(), e),
                ])
            }
            Id::EC => {
                let (crv, x, y) = self.as_ec_jwk_parts();
                HashMap::from([
                    (JWK_KEY_KTY.into(), JWK_KTY_EC.into()),
                    (JWK_KEY_CRV.into(), crv.into()),
                    (JWK_KEY_X.into(), x.to_base64().unwrap().into()),
                    (JWK_KEY_Y.into(), y.to_base64().unwrap().into()),
                ])
            }
            _ => panic!("Invalid algorithm type"),
        };

        serde_json::to_value(raw).unwrap()
    }

    fn thumbprint(&self) -> String {
        let hash_input = match self.key.id() {
            Id::RSA => {
                let (n, e) = self.as_rsa_jwk_parts();
                format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
            }
            Id::EC => {
                let (crv, x, y) = self.as_ec_jwk_parts();
                format!(r#"{{"crv":"{}","kty":"EC","n":"{}","n":"{}"}}"#, crv, x, y)
            }
            _ => panic!("Invalid algorithm type"),
        };

        HashAlgorithmType::Sha256.hash(hash_input)
    }
}

impl SigningAlgorithm for PKeyWithDigest<Private> {
    fn algorithm_type(&self) -> AlgorithmType {
        PKeyWithDigest::algorithm_type(self)
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        let signer_signature = match self.algorithm_type() {
            // for EdDSA, openssl needs to be told that no digest type is in use, as passing NULL
            // is not enough.
            AlgorithmType::EdDSA => {
                let mut signer = Signer::new_without_digest(&self.key)?;

                signer.sign_oneshot_to_vec(super::make_body(header, claims).as_slice())?
            },
            _ => {
                let mut signer = Signer::new(self.digest.clone(), &self.key)?;
                signer.update(header.as_bytes())?;
                signer.update(SEPARATOR.as_bytes())?;
                signer.update(claims.as_bytes())?;
                signer.sign_to_vec()?
            }
        };

        // note that Ed25519 signatures do not need to be converted to/from a DER format
        let signature = if self.key.id() == Id::EC {
            der_to_jose(&signer_signature)?
        } else {
            signer_signature
        };

        Ok(base64::encode_config(&signature, base64::URL_SAFE_NO_PAD))
    }
}

impl VerifyingAlgorithm for PKeyWithDigest<Public> {
    fn algorithm_type(&self) -> AlgorithmType {
        PKeyWithDigest::algorithm_type(self)
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        match self.algorithm_type() {
            // for EdDSA, openssl needs to be told that no digest type is in use, as passing NULL
            // is not enough.
            AlgorithmType::EdDSA => {
                let mut verifier = Verifier::new_without_digest(&self.key)?;

                // note that Ed25519 signatures do not need to be converted to/from a DER format
                let verified = verifier.verify_oneshot(signature, super::make_body(header, claims).as_slice())?;

                Ok(verified)
            },
            _ => {
                let mut verifier = Verifier::new(self.digest.clone(), &self.key)?;
                verifier.update(header.as_bytes())?;
                verifier.update(SEPARATOR.as_bytes())?;
                verifier.update(claims.as_bytes())?;

                let verified = if self.key.id() == Id::EC {
                    let der = jose_to_der(signature)?;
                    verifier.verify(&der)?
                } else {
                    verifier.verify(signature)?
                };

                Ok(verified)
            }
        }
    }
}

/// OpenSSL by default signs ECDSA in DER, but JOSE expects them in a concatenated (R, S) format
fn der_to_jose(der: &[u8]) -> Result<Vec<u8>, Error> {
    let signature = EcdsaSig::from_der(&der)?;
    let r = signature.r().to_vec();
    let s = signature.s().to_vec();
    Ok([r, s].concat())
}

/// OpenSSL by default verifies ECDSA in DER, but JOSE parses out a concatenated (R, S) format
fn jose_to_der(jose: &[u8]) -> Result<Vec<u8>, Error> {
    let (r, s) = jose.split_at(jose.len() / 2);
    let ecdsa_signature =
        EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
    Ok(ecdsa_signature.to_der()?)
}

#[cfg(test)]
mod tests {
    use crate::algorithm::openssl::PKeyWithDigest;
    use crate::algorithm::AlgorithmType::*;
    use crate::algorithm::{SigningAlgorithm, VerifyingAlgorithm};
    use crate::error::Error;
    use crate::header::PrecomputedAlgorithmOnlyHeader as AlgOnly;
    use crate::ToBase64;

    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;

    // {"sub":"1234567890","name":"John Doe","admin":true}
    const CLAIMS: &'static str =
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    const RS256_SIGNATURE: &'static str =
    "cQsAHF2jHvPGFP5zTD8BgoJrnzEx6JNQCpupebWLFnOc2r_punDDTylI6Ia4JZNkvy2dQP-7W-DEbFQ3oaarHsDndqUgwf9iYlDQxz4Rr2nEZX1FX0-FMEgFPeQpdwveCgjtTYUbVy37ijUySN_rW-xZTrsh_Ug-ica8t-zHRIw";

    #[test]
    fn rs256_sign() -> Result<(), Error> {
        let pem = include_bytes!("../../test/rs256-private.pem");

        let algorithm = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::private_key_from_pem(pem)?,
        };

        let result = algorithm.sign(&AlgOnly(Rs256).to_base64()?, CLAIMS)?;
        assert_eq!(result, RS256_SIGNATURE);
        Ok(())
    }

    #[test]
    fn rs256_verify() -> Result<(), Error> {
        let pem = include_bytes!("../../test/rs256-public.pem");

        let algorithm = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::public_key_from_pem(pem)?,
        };

        let verification_result =
            algorithm.verify(&AlgOnly(Rs256).to_base64()?, CLAIMS, RS256_SIGNATURE)?;
        assert!(verification_result);
        Ok(())
    }

    #[test]
    fn es256() -> Result<(), Error> {
        let private_pem = include_bytes!("../../test/es256-private.pem");
        let private_key = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::private_key_from_pem(private_pem)?,
        };

        let signature = private_key.sign(&AlgOnly(Es256).to_base64()?, CLAIMS)?;

        let public_pem = include_bytes!("../../test/es256-public.pem");

        let public_key = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::public_key_from_pem(public_pem)?,
        };

        let verification_result =
            public_key.verify(&AlgOnly(Es256).to_base64()?, CLAIMS, &*signature)?;
        assert!(verification_result);
        Ok(())
    }

    #[test]
    fn eddsa() -> Result<(), Error> {
        let private_pem = include_bytes!("../../test/eddsa-private.pem");

        let private_key = PKeyWithDigest {
            digest: MessageDigest::null(),
            key: PKey::private_key_from_pem(private_pem)?,
        };

        let signature = private_key.sign(&AlgOnly(EdDSA).to_base64()?, CLAIMS)?;

        let public_pem = include_bytes!("../../test/eddsa-public.pem");

        let public_key = PKeyWithDigest {
            digest: MessageDigest::null(),
            key: PKey::public_key_from_pem(public_pem)?,
        };

        let verification_result =
            public_key.verify(&AlgOnly(EdDSA).to_base64()?, CLAIMS, &*signature)?;
        assert!(verification_result);
        Ok(())
    }
}
