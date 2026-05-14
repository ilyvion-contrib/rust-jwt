//! RustCrypto implementations of signing and verifying algorithms.
//! According to that organization, only hmac is safely implemented at the
//! moment.

use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore},
    generic_array::typenum::{IsLess, Le, NonZero},
    HashMarker,
};
use hmac::{Hmac, Mac};

use crate::algorithm::{
    AlgorithmType, HashAlgorithm, HashAlgorithmType, SigningAlgorithm, VerifyingAlgorithm,
};
use crate::error::Error;
use crate::SEPARATOR;

/// A trait used to make the implementation of `SigningAlgorithm` and
/// `VerifyingAlgorithm` easier.
/// RustCrypto crates tend to have algorithm types defined at the type level,
/// so they cannot accept a self argument.
pub trait TypeLevelAlgorithmType {
    fn algorithm_type() -> AlgorithmType;
}

macro_rules! type_level_algorithm_type {
    ($rust_crypto_type: ty, $algorithm_type: expr) => {
        impl TypeLevelAlgorithmType for $rust_crypto_type {
            fn algorithm_type() -> AlgorithmType {
                $algorithm_type
            }
        }
    };
}

type_level_algorithm_type!(sha2::Sha256, AlgorithmType::Hs256);
type_level_algorithm_type!(sha2::Sha384, AlgorithmType::Hs384);
type_level_algorithm_type!(sha2::Sha512, AlgorithmType::Hs512);

impl<D> SigningAlgorithm for Hmac<D>
where
    D: CoreProxy + TypeLevelAlgorithmType,
    D::Core: HashMarker
        + BufferKindUser<BufferKind = Eager>
        + FixedOutputCore
        + digest::Reset
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn algorithm_type(&self) -> AlgorithmType {
        D::algorithm_type()
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        let hmac = get_hmac_with_data(self, header, claims);
        let mac_result = hmac.finalize();
        let code = mac_result.into_bytes();
        Ok(base64::encode_config(&code, base64::URL_SAFE_NO_PAD))
    }
}

impl<D> VerifyingAlgorithm for Hmac<D>
where
    D: CoreProxy + TypeLevelAlgorithmType,
    D::Core: HashMarker
        + BufferKindUser<BufferKind = Eager>
        + FixedOutputCore
        + digest::Reset
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn algorithm_type(&self) -> AlgorithmType {
        D::algorithm_type()
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        let hmac = get_hmac_with_data(self, header, claims);
        hmac.verify_slice(signature)?;
        Ok(true)
    }
}

fn get_hmac_with_data<D>(hmac: &Hmac<D>, header: &str, claims: &str) -> Hmac<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + BufferKindUser<BufferKind = Eager>
        + FixedOutputCore
        + digest::Reset
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut hmac = hmac.clone();
    hmac.reset();
    hmac.update(header.as_bytes());
    hmac.update(SEPARATOR.as_bytes());
    hmac.update(claims.as_bytes());
    hmac
}

/// A trait used to make the implementation of `HashAlgorithm` easier.
pub trait TypeLevelHashAlgorithmType {
    fn hash_algorithm_type() -> HashAlgorithmType;
}

macro_rules! type_level_hash_algorithm_type {
    ($rust_crypto_type: ty, $hash_algorithm_type: expr) => {
        impl TypeLevelHashAlgorithmType for $rust_crypto_type {
            fn hash_algorithm_type() -> HashAlgorithmType {
                $hash_algorithm_type
            }
        }
    };
}

type_level_hash_algorithm_type!(sha2::Sha256, HashAlgorithmType::Sha256);
type_level_hash_algorithm_type!(sha2::Sha384, HashAlgorithmType::Sha384);
type_level_hash_algorithm_type!(sha2::Sha512, HashAlgorithmType::Sha512);

impl HashAlgorithmType {
    fn hash<D: sha2::Digest>(data: impl AsRef<[u8]>) -> String {
        let hash = D::digest(data);
        base64::encode_config(&hash, base64::URL_SAFE_NO_PAD)
    }
}

impl HashAlgorithm for HashAlgorithmType {
    fn hash_algorithm_type(&self) -> HashAlgorithmType {
        *self
    }

    fn hash(&self, data: impl AsRef<[u8]>) -> String {
        match self {
            HashAlgorithmType::Sha256 => Self::hash::<sha2::Sha256>(data),
            HashAlgorithmType::Sha384 => Self::hash::<sha2::Sha384>(data),
            HashAlgorithmType::Sha512 => Self::hash::<sha2::Sha512>(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::{
        HashAlgorithm, HashAlgorithmType, SigningAlgorithm, VerifyingAlgorithm,
    };
    use crate::error::Error;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[test]
    pub fn sign() -> Result<(), Error> {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let expected_signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

        let signer: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        let computed_signature = SigningAlgorithm::sign(&signer, header, claims)?;

        assert_eq!(computed_signature, expected_signature);
        Ok(())
    }

    #[test]
    pub fn verify() -> Result<(), Error> {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

        let verifier: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        assert!(VerifyingAlgorithm::verify(
            &verifier, header, claims, signature
        )?);
        Ok(())
    }

    #[test]
    pub fn hash() -> Result<(), Error> {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let expected256 = "0yjVF-CQYNGq008_sS2Cq46aFdgQMmOGmHWK3ThalFQ";
        let expected384 = "rq15ikLx7wdNTa-hJyb1h-bYKf7UDytFnchjyljXrDPYkyezDA_ObYDSHuOUExWw";
        let expected512 = "2eCqV6wY58t5LN2bOvE8c4ewW7yA9UH9A4fow7z6AVwxdJqdlvgS8bJ-1wmeZBe6Es5rdqAi--U7p8SHDrcH7Q";

        let hash = HashAlgorithmType::Sha256;
        assert_eq!(hash.hash_algorithm_type(), HashAlgorithmType::Sha256);
        assert_eq!(hash.hash(data), expected256);

        let hash = HashAlgorithmType::Sha384;
        assert_eq!(hash.hash_algorithm_type(), HashAlgorithmType::Sha384);
        assert_eq!(hash.hash(data), expected384);

        let hash = HashAlgorithmType::Sha512;
        assert_eq!(hash.hash_algorithm_type(), HashAlgorithmType::Sha512);
        assert_eq!(hash.hash(data), expected512);

        Ok(())
    }
}
