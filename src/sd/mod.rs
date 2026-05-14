use crate::algorithm::{
    random_data, HashAlgorithm, HashAlgorithmType, KeyConfirmation, KeyConfirmationAlgorithm,
    SigningAlgorithm, VerifyingAlgorithm,
};
use crate::error::Error;
use crate::header::{Header, HeaderType, JoseHeader};
use crate::token::signed::SignWithKey;
use crate::token::verified::VerifyWithKey;
use crate::token::{Signed, Unsigned, Unverified, Verified};
use crate::{FromBase64, ToBase64};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;
const SEPARATOR: &str = "~";
const REDACTION_LIST_FIELD: &str = "_sd";
const CONFIRMATION_KEY_FIELD: &str = "cnf";
const REDACTION_ALG_FIELD: &str = "_sd_alg";

#[derive(Serialize, Deserialize)]
struct Redaction {
    #[serde(rename = "...")]
    hash: String,
}

#[derive(Debug, Clone)]
struct Disclosure {
    key: Option<String>,
    value: Value,
    hash_input: Vec<u8>,
}

impl Disclosure {
    fn new(key: Option<String>, value: Value) -> Result<Self, Error> {
        let mut parts: Vec<Value> = Vec::with_capacity(3);

        let salt = random_data(SALT_SIZE);

        parts.push(salt.into());
        key.as_ref().map(|k| parts.push(k.clone().into()));
        parts.push(value.clone());

        let hash_input = serde_json::to_vec(&parts)?;

        Ok(Self {
            key,
            value,
            hash_input,
        })
    }

    fn hash(&self, sd_alg: &impl HashAlgorithm) -> String {
        sd_alg.hash(&self.hash_input)
    }

    fn as_value(&self, sd_alg: &impl HashAlgorithm) -> Result<Value, Error> {
        let hash = self.hash(sd_alg);
        serde_json::to_value(Redaction { hash }).map_err(|e| Error::Json(e))
    }
}

impl ToBase64 for Disclosure {
    fn to_base64(&self) -> Result<Cow<str>, Error> {
        let encoded_json_bytes = base64::encode_config(&self.hash_input, base64::URL_SAFE_NO_PAD);
        Ok(Cow::Owned(encoded_json_bytes))
    }
}

impl FromBase64 for Disclosure {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error> {
        let hash_input = base64::decode_config(raw, base64::URL_SAFE_NO_PAD)?;

        let mut values: Vec<Value> = serde_json::from_slice(&hash_input)?;
        if values.len() != 2 && values.len() != 3 {
            return Err(Error::InvalidDisclosure);
        }

        // Discard the salt; it just stays in hash_input
        values.remove(0);

        // Capture the value
        let value = values.pop().unwrap();

        // Capture the key if present
        let key: Option<String> = values
            .pop()
            .map(|x| serde_json::from_value(x))
            .transpose()?;

        Ok(Self {
            key,
            value,
            hash_input: hash_input,
        })
    }
}

trait Redactable {
    fn find_container<'a>(&'a mut self, hash: String) -> Option<&'a mut Value>;
    fn find_sd_hash(
        &self,
        _pointer: &str,
        sd_alg: &impl HashAlgorithm,
        disclosures: &[Disclosure],
    ) -> Option<usize>;
    fn redact(&mut self, pointer: &str, sd_alg: &impl HashAlgorithm) -> Result<Disclosure, Error>;
    fn unredact(
        &mut self,
        disclosure: Disclosure,
        sd_alg: &impl HashAlgorithm,
    ) -> Result<(), Error>;
}

impl Redactable for Value {
    fn find_container<'a>(&'a mut self, hash: String) -> Option<&'a mut Value> {
        // XXX(RLB) The arrangement of code here is somewhat infelicitous, but necessary to avoid
        // double borrows.
        let found = match self {
            Value::Object(map) => {
                let hash_value = serde_json::to_value(hash.clone()).unwrap();
                if let Some(Value::Array(vec)) = map.get(REDACTION_LIST_FIELD) {
                    vec.contains(&hash_value)
                } else {
                    false
                }
            }
            Value::Array(vec) => {
                let redaction = Redaction { hash: hash.clone() };
                let redaction_value = serde_json::to_value(redaction).unwrap();
                vec.contains(&redaction_value)
            }
            _ => false,
        };

        if found {
            return Some(self);
        }

        if self.is_array() {
            return self
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .map(|v| v.find_container(hash.clone()))
                .find(|opt| opt.is_some())
                .flatten();
        }

        if self.is_object() {
            return self
                .as_object_mut()
                .unwrap()
                .iter_mut()
                .map(|(_k, v)| v.find_container(hash.clone()))
                .find(|opt| opt.is_some())
                .flatten();
        }

        None
    }

    fn find_sd_hash(
        &self,
        pointer: &str,
        sd_alg: &impl HashAlgorithm,
        disclosures: &[Disclosure],
    ) -> Option<usize> {
        let cut = pointer.rfind("/")?;
        let (container_ptr, elem_ptr) = pointer.split_at(cut);

        let container = self.pointer(container_ptr)?;
        match container {
            Value::Array(_) => {
                let value = container.pointer(elem_ptr)?;
                let redaction: Redaction = serde_json::from_value(value.clone()).ok()?;
                let hash = redaction.hash;
                disclosures.iter().position(|d| d.hash(sd_alg) == hash)
            }
            Value::Object(map) => {
                let sd = map.get(REDACTION_LIST_FIELD)?;
                let sd_array: Vec<_> = sd.as_array()?.iter().map(|d| d.as_str()).collect();

                let key: String = elem_ptr[1..].into();
                disclosures.iter().position(|d| {
                    if d.key != Some(key.clone()) {
                        return false;
                    }

                    let hash = d.hash(sd_alg);
                    sd_array.contains(&Some(&hash))
                })
            }
            _ => return None,
        }
    }

    fn redact(&mut self, pointer: &str, sd_alg: &impl HashAlgorithm) -> Result<Disclosure, Error> {
        let cut = pointer.rfind("/").ok_or(Error::InvalidPointer)?;
        let (container_ptr, elem_ptr) = pointer.split_at(cut);

        let container = self
            .pointer_mut(container_ptr)
            .ok_or(Error::InvalidPointer)?;
        match container {
            Value::Array(_) => {
                let value = container
                    .pointer_mut(elem_ptr)
                    .ok_or(Error::InvalidPointer)?;
                let disclosure = Disclosure::new(None, value.take())?;
                *value = disclosure.as_value(sd_alg)?;
                Ok(disclosure)
            }
            Value::Object(map) => {
                let key: String = elem_ptr[1..].into();
                let value = map.get_mut(&key).ok_or(Error::InvalidPointer)?;
                let disclosure = Disclosure::new(Some(key.clone()), value.take())?;

                map.remove(&key);

                let hash_value =
                    serde_json::to_value(disclosure.hash(sd_alg)).map_err(|e| Error::Json(e))?;
                let _sd = map.entry(REDACTION_LIST_FIELD).or_insert(json!([]));
                _sd.as_array_mut()
                    .ok_or(Error::InvalidPointer)?
                    .push(hash_value);

                Ok(disclosure)
            }
            _ => return Err(Error::InvalidPointer),
        }
    }

    fn unredact(
        &mut self,
        disclosure: Disclosure,
        sd_alg: &impl HashAlgorithm,
    ) -> Result<(), Error> {
        let hash = disclosure.hash(sd_alg);
        let container = self
            .find_container(hash.clone())
            .ok_or(Error::InvalidDisclosure)?;

        match container {
            Value::Array(vec) => {
                if disclosure.key.is_some() {
                    return Err(Error::InvalidDisclosure);
                }

                // Replace the redacted value with the disclosed value
                let redaction = Redaction { hash: hash.clone() };
                let redaction_value = serde_json::to_value(redaction).unwrap();
                vec.iter_mut()
                    .find(|x| **x == redaction_value)
                    .map(|x| *x = disclosure.value);
                Ok(())
            }
            Value::Object(map) => {
                // Restore the disclosed field to the object
                let key = disclosure.key.ok_or(Error::InvalidDisclosure)?;
                map.insert(key, disclosure.value);

                // Remove the disclosed field from the _sd list
                let hash_value = serde_json::to_value(hash.clone()).unwrap();
                let _sd = map
                    .get_mut(REDACTION_LIST_FIELD)
                    .unwrap()
                    .as_array_mut()
                    .unwrap();
                let index = _sd.iter().position(|x| *x == hash_value).unwrap();
                _sd.remove(index);

                // Clean up the _sd field if it is no longer needed
                if _sd.len() == 0 {
                    map.remove(REDACTION_LIST_FIELD);
                }

                Ok(())
            }
            _ => Err(Error::InvalidDisclosure),
        }
    }
}

/// A type that allows array entries to be marked as optionally redacted.  Only supports
/// optionality on deserialization, not serialization, since serializing requires that you know the
/// proper hash value for the redaction.
#[derive(Serialize, Deserialize)] // TODO
pub struct OptionallyRedactedArrayEntry<T>(Option<T>);

type IssuerJwt<H, S> = crate::Token<H, Value, S>;

#[derive(Serialize, Deserialize)]
struct StandardClaims {
    _sd_alg: HashAlgorithmType,
    cnf: Option<KeyConfirmation>,
}

/// Representation of a structured JWT. Methods vary based on the signature
/// type `S`.
pub struct Token<H, C, S> {
    issuer_jwt: IssuerJwt<H, S>,
    disclosures: Vec<Disclosure>,
    sd_alg: HashAlgorithmType,
    signature: S,
    _phantom: PhantomData<C>,
}

impl<H, C, S> Token<H, C, S> {
    pub fn issuer_jwt(&self) -> &IssuerJwt<H, S> {
        &self.issuer_jwt
    }

    pub fn remove_signature(self) -> Token<H, C, Unsigned> {
        Token {
            issuer_jwt: self.issuer_jwt.remove_signature(),
            disclosures: self.disclosures,
            sd_alg: self.sd_alg,
            signature: Unsigned,
            _phantom: Default::default(),
        }
    }

    fn matches_confirmation_key(&self, key: &impl KeyConfirmationAlgorithm) -> Result<(), Error> {
        let raw_claims = self.issuer_jwt.claims().clone();
        let claims: StandardClaims =
            serde_json::from_value(raw_claims).map_err(|e| Error::Json(e))?;
        let cnf = claims.cnf.ok_or(Error::InvalidConfirmationKey)?;
        cnf.matches(key)
            .then(|| ())
            .ok_or(Error::InvalidConfirmationKey)
    }
}

impl<H, C, S> Clone for Token<H, C, S>
where
    H: Clone,
    C: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            issuer_jwt: self.issuer_jwt.clone(),
            disclosures: self.disclosures.clone(),
            sd_alg: self.sd_alg.clone(),
            signature: self.signature.clone(),
            _phantom: Default::default(),
        }
    }
}

impl<H, C: Serialize> Token<H, C, Unsigned> {
    /// Create a new unsigned token, with mutable headers and claims.
    pub fn new(header: H, claims: C, sd_alg: HashAlgorithmType) -> Result<Self, Error> {
        let mut value = serde_json::to_value(claims)?;
        if let Value::Object(map) = &mut value {
            let alg_value = serde_json::to_value(sd_alg)?;
            map.insert(REDACTION_ALG_FIELD.into(), alg_value);
        } else {
            return Err(Error::InvalidClaims);
        }

        Ok(Token {
            issuer_jwt: IssuerJwt::new(header, value),
            disclosures: Default::default(),
            sd_alg,
            signature: Unsigned,
            _phantom: Default::default(),
        })
    }

    pub fn issuer_jwt_mut(&mut self) -> &mut IssuerJwt<H, Unsigned> {
        &mut self.issuer_jwt
    }

    pub fn redact(&mut self, pointer: &str) -> Result<(), Error> {
        // Split the JSON pointer into the container and the field within the container
        let claims = self.issuer_jwt.claims_mut();
        let disclosure = claims.redact(pointer, &self.sd_alg)?;
        self.disclosures.push(disclosure);
        Ok(())
    }

    pub fn set_confirmation_key(&mut self, cnf: KeyConfirmation) -> Result<(), Error> {
        let claims = self.issuer_jwt.claims_mut().as_object_mut().unwrap();
        let cnf_value = serde_json::to_value(cnf).map_err(|e| Error::Json(e))?;
        claims.insert(CONFIRMATION_KEY_FIELD.into(), cnf_value);
        Ok(())
    }
}

impl<H, C> SignWithKey<Token<H, C, Signed>> for Token<H, C, Unsigned>
where
    H: ToBase64 + JoseHeader,
    C: ToBase64,
{
    fn sign_with_key(self, key: &impl SigningAlgorithm) -> Result<Token<H, C, Signed>, Error> {
        let issuer_jwt = self.issuer_jwt.sign_with_key(key)?;
        let mut token = Token {
            issuer_jwt: issuer_jwt,
            disclosures: self.disclosures,
            sd_alg: self.sd_alg,
            signature: Signed {
                token_string: Default::default(),
            },
            _phantom: Default::default(),
        };

        token.reserialize()?;
        Ok(token)
    }
}

impl<H, C> Token<H, C, Signed> {
    /// Get the string representation of the token.
    pub fn as_str(&self) -> &str {
        &self.signature.token_string
    }

    /// Remove the selective disclosure for the element at the given JSON pointer
    fn forget(&mut self, pointer: &str) -> Result<(), Error> {
        let to_delete = self
            .issuer_jwt
            .claims()
            .find_sd_hash(pointer, &self.sd_alg, &self.disclosures)
            .ok_or(Error::InvalidPointer)?;

        self.disclosures.remove(to_delete);
        self.reserialize()
    }

    /// Remove all selective disclosures
    fn forget_all(&mut self) -> Result<(), Error> {
        self.disclosures.clear();
        self.reserialize()
    }
}

impl<H, C> Token<H, C, Signed>
where
    H: FromBase64,
    C: FromBase64,
{
    /// Get a view of this token as unverified, so that it can be verified again
    pub fn as_unverified(&self) -> Result<Token<H, C, Unverified>, Error> {
        let signature = Unverified {
            header_str: &"",
            claims_str: &"",
            signature_str: &"",
        };

        Ok(Token {
            issuer_jwt: self.issuer_jwt.as_unverified()?,
            disclosures: self.disclosures.clone(),
            sd_alg: self.sd_alg.clone(),
            signature,
            _phantom: Default::default(),
        })
    }
}

impl<H, C> From<Token<H, C, Signed>> for String {
    fn from(token: Token<H, C, Signed>) -> Self {
        token.signature.token_string
    }
}

impl<'a, H, C> From<Token<H, C, Unverified<'a>>> for Token<H, C, Signed> {
    fn from(token: Token<H, C, Unverified<'a>>) -> Self {
        let mut token = Token {
            issuer_jwt: token.issuer_jwt.into(),
            disclosures: token.disclosures,
            sd_alg: token.sd_alg,
            signature: Signed {
                token_string: Default::default(),
            },
            _phantom: Default::default(),
        };

        token.reserialize().unwrap();
        token
    }
}

impl<H, C> Token<H, C, Signed> {
    fn reserialize(&mut self) -> Result<(), Error> {
        let disclosures = self
            .disclosures
            .iter()
            .map(|d| d.to_base64())
            .collect::<Result<Vec<_>, _>>()?;

        let mut parts = disclosures;
        parts.insert(0, self.issuer_jwt.as_str().into()); // issuer JWT comes first
        parts.push("".into()); // empty key binding comes last

        self.signature.token_string = parts.join(SEPARATOR);
        Ok(())
    }
}

impl<'a, H: FromBase64, C: FromBase64> Token<H, C, Unverified<'a>> {
    /// Not recommended. Parse the header and claims without checking the validity of the signature.
    pub fn parse_unverified(token_str: &str) -> Result<Token<H, C, Unverified>, Error> {
        let mut components = token_str.split(SEPARATOR);
        let issuer_jwt = components.next().ok_or(Error::NoIssuerJwt)?;

        let mut raw_disclosures: Vec<String> = components.map(|s| s.into()).collect();
        let last_entry = raw_disclosures.last();
        if last_entry.is_none() || last_entry.unwrap() != "" {
            // XXX(RLB): It seems like Option should have a more elegant flavor of the above
            println!("No last entry");
            return Err(Error::InvalidKeyBinding);
        }
        raw_disclosures.pop();

        let issuer_jwt: IssuerJwt<H, _> = crate::Token::parse_unverified(issuer_jwt)?;
        let disclosures: Vec<Disclosure> = raw_disclosures
            .iter()
            .map(|d| Disclosure::from_base64(d))
            .collect::<Result<Vec<_>, _>>()?;
        // We only need this field for type alignment with issuer_jwt
        let signature = Unverified {
            header_str: &"",
            claims_str: &"",
            signature_str: &"",
        };

        let raw_claims = issuer_jwt.claims().clone();
        let standard_claims: StandardClaims = serde_json::from_value(raw_claims)?;

        Ok(Token {
            issuer_jwt,
            disclosures,
            signature,
            sd_alg: standard_claims._sd_alg,
            _phantom: Default::default(),
        })
    }
}

impl<'a, H: JoseHeader, C> VerifyWithKey<Token<H, C, Verified>> for Token<H, C, Unverified<'a>> {
    fn verify_with_key(
        self,
        key: &impl VerifyingAlgorithm,
    ) -> Result<Token<H, C, Verified>, Error> {
        let issuer_jwt = self.issuer_jwt.verify_with_key(key)?;
        Ok(Token {
            issuer_jwt,
            disclosures: self.disclosures,
            sd_alg: self.sd_alg,
            signature: Verified,
            _phantom: Default::default(),
        })
    }
}

impl<H, C: for<'de> Deserialize<'de> + Sized> Token<H, C, Verified> {
    pub fn reveal(self) -> Result<C, Error> {
        let (_header, mut claims) = self.issuer_jwt.into();

        for disclosure in self.disclosures.into_iter() {
            claims.unredact(disclosure, &self.sd_alg)?;
        }

        serde_json::from_value(claims).map_err(|e| Error::Json(e))
    }
}

fn key_binding_header(key: &impl SigningAlgorithm) -> Header {
    Header {
        algorithm: key.algorithm_type(),
        key_id: None,
        type_: Some(HeaderType::KeyBindingJwt),
        content_type: None,
    }
}

#[derive(Default, Serialize, Deserialize)]
struct KeyBindingClaims {
    iat: u64,
    aud: String,
    nonce: String,
    _sd_hash: String, // XXX-SPEC: The underscore seems unnecessary
}

type KeyBindingJwt<S> = crate::Token<Header, KeyBindingClaims, S>;

pub struct Presentation<H, C, S> {
    token: Token<H, C, Signed>,
    kb_jwt: KeyBindingJwt<S>,
    signature: S,
}

impl<H, C> Presentation<H, C, Unsigned> {
    pub fn new(token: Token<H, C, Signed>, aud: String) -> Self {
        let mut presentation = Self {
            token: token,
            kb_jwt: Default::default(),
            signature: Unsigned,
        };

        let claims = presentation.kb_jwt.claims_mut();
        claims.aud = aud;

        presentation
    }
}

// XXX(RLB) This is a hack around not being able to include multiple types in an `impl` parameter
// declaration.
pub trait KeyConfirmationAndSigningAlgorithm: SigningAlgorithm + KeyConfirmationAlgorithm {}

impl<T> KeyConfirmationAndSigningAlgorithm for T where T: SigningAlgorithm + KeyConfirmationAlgorithm
{}

// XXX(RLB) This is a hack around not being able to include multiple types in an `impl` parameter
// declaration.
pub trait KeyConfirmationAndVerifyingAlgorithm:
    VerifyingAlgorithm + KeyConfirmationAlgorithm
{
}

impl<T> KeyConfirmationAndVerifyingAlgorithm for T where
    T: VerifyingAlgorithm + KeyConfirmationAlgorithm
{
}

impl<H, C> Presentation<H, C, Unsigned> {
    pub fn sign_with_key(
        self,
        key: &impl KeyConfirmationAndSigningAlgorithm,
    ) -> Result<Presentation<H, C, Signed>, Error> {
        // Verify that the key matches the issuer JWT
        let sd_alg = self.token.sd_alg;
        let token_str = self.token.as_str();
        self.token.matches_confirmation_key(key)?;

        // Set up and sign the Key Binding JWT
        let mut kb_jwt = self.kb_jwt;

        let header = kb_jwt.header_mut();
        *header = key_binding_header(key);

        let claims = kb_jwt.claims_mut();
        claims.iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        claims.nonce = random_data(NONCE_SIZE);
        claims._sd_hash = sd_alg.hash(&token_str);

        let kb_jwt = kb_jwt.sign_with_key(key)?;

        // Assemble the token string
        let token_string = self.token.signature.token_string.clone() + kb_jwt.as_str();

        Ok(Presentation {
            token: self.token,
            kb_jwt: kb_jwt,
            signature: Signed { token_string },
        })
    }

    /// Remove the selective disclosure for the element at the given JSON pointer
    pub fn forget(&mut self, pointer: &str) -> Result<(), Error> {
        self.token.forget(pointer)
    }

    /// Remove all selective disclosures
    pub fn forget_all(&mut self) -> Result<(), Error> {
        self.token.forget_all()
    }
}

impl<H, C> Presentation<H, C, Signed> {
    /// Get the string representation of the presentation.
    pub fn as_str(&self) -> &str {
        &self.signature.token_string
    }
}

impl<H, C> From<Presentation<H, C, Signed>> for String {
    fn from(presentation: Presentation<H, C, Signed>) -> Self {
        presentation.signature.token_string
    }
}

impl<'a, H: FromBase64, C: FromBase64> Presentation<H, C, Unverified<'a>> {
    /// Not recommended. Parse the header and claims without checking the validity of the signature.
    pub fn parse_unverified(
        presentation_str: &'a str,
    ) -> Result<Presentation<H, C, Unverified>, Error> {
        let cut = presentation_str
            .rfind("~")
            .ok_or(Error::InvalidPresentation)?;
        if cut == presentation_str.len() - 1 {
            return Err(Error::InvalidPresentation);
        }
        let (token_str, kb_jwt_str) = presentation_str.split_at(cut + 1);

        let token: Token<H, C, _> = Token::parse_unverified(token_str)?;
        let token: Token<H, C, Signed> = token.into();
        let kb_jwt: KeyBindingJwt<Unverified<'a>> = crate::Token::parse_unverified(kb_jwt_str)?;
        let signature = Unverified {
            header_str: &"",
            claims_str: &"",
            signature_str: &"",
        };

        Ok(Self {
            token,
            kb_jwt,
            signature,
        })
    }
}

impl<'a, H, C> Presentation<H, C, Unverified<'a>> {
    pub fn verify_with_key(
        self,
        key: &impl KeyConfirmationAndVerifyingAlgorithm,
    ) -> Result<Presentation<H, C, Verified>, Error> {
        // Verify that the key matches the issuer JWT
        let sd_alg = self.token.sd_alg;
        let token_str = self.token.as_str();
        self.token.matches_confirmation_key(key)?;

        // Verify the KB JWT
        let kb_jwt = self.kb_jwt.verify_with_key(key)?;

        // Verify that the SD corresponds to the issuer JWT
        let sd_hash = sd_alg.hash(&token_str);
        let claims = kb_jwt.claims();
        if sd_hash != claims._sd_hash {
            println!("Invalid SD hash match {} != {}", sd_hash, claims._sd_hash);
            return Err(Error::InvalidKeyBinding);
        }

        Ok(Presentation {
            token: self.token,
            kb_jwt,
            signature: Verified,
        })
    }
}

impl<H: FromBase64, C: FromBase64> Presentation<H, C, Verified> {
    pub fn token(self) -> Token<H, C, Signed> {
        self.token
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::{
        openssl::PKeyWithDigest, AlgorithmType, HashAlgorithmType, KeyConfirmationAlgorithm,
        SigningAlgorithm,
    };
    use crate::error::Error;
    use crate::header::Header;
    use crate::sd::{Presentation, Redactable, Token, REDACTION_LIST_FIELD};
    use crate::token::signed::SignWithKey;
    use crate::token::verified::VerifyWithKey;
    use crate::Claims;
    use hmac::Hmac;
    use hmac::Mac;
    use openssl::pkey::{Private, Public};
    use serde_json::{json, Value};
    use sha2::Sha256;

    fn generate_key_pair() -> (PKeyWithDigest<Private>, PKeyWithDigest<Public>) {
        use openssl::{
            ec::{EcGroup, EcKey},
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
        };

        let p256 = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_issuer_priv = EcKey::generate(&p256).unwrap();
        let pub_pt = ec_issuer_priv.public_key();
        let ec_issuer_pub = EcKey::from_public_key(&p256, &pub_pt).unwrap();

        let issuer_priv = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::from_ec_key(ec_issuer_priv).unwrap(),
        };
        let issuer_pub = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::from_ec_key(ec_issuer_pub).unwrap(),
        };

        (issuer_priv, issuer_pub)
    }

    #[test]
    pub fn raw_data_no_disclosures() -> Result<(), Error> {
        let raw = "eyJhbGciOiJIUzI1NiJ9.eyJfc2RfYWxnIjoic2hhLTI1NiJ9.TVSrPRIvhNXpPPVyx2JUDgT7JloWGpx42xZ6lxq5GfM~";
        let token: Token<Header, Claims, _> = Token::parse_unverified(raw)?;

        assert_eq!(token.issuer_jwt().header().algorithm, AlgorithmType::Hs256);

        let verifier: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        let verified = token.verify_with_key(&verifier)?;
        verified.reveal()?;

        Ok(())
    }

    #[test]
    pub fn roundtrip_no_disclosures() -> Result<(), Error> {
        let (issuer_priv, issuer_pub) = generate_key_pair();
        let sd_alg = HashAlgorithmType::Sha256;
        let header = Header {
            algorithm: issuer_priv.algorithm_type(),
            key_id: None,
            type_: None,
            content_type: None,
        };

        let token: Token<Header, Claims, _> = Token::new(header, Default::default(), sd_alg)?;
        let signed_token = token.sign_with_key(&issuer_priv)?;
        let signed_token_str = signed_token.as_str();

        let recreated_token: Token<Header, Claims, _> = Token::parse_unverified(signed_token_str)?;

        assert_eq!(
            signed_token.issuer_jwt().header(),
            recreated_token.issuer_jwt().header()
        );
        assert_eq!(
            signed_token.issuer_jwt().claims(),
            recreated_token.issuer_jwt().claims()
        );
        recreated_token.verify_with_key(&issuer_pub)?;
        Ok(())
    }

    #[test]
    pub fn array_redact_unredact_round_trip() -> Result<(), Error> {
        let sd_alg = HashAlgorithmType::Sha256;

        let array_original = json!(["US", "DE", "CZ"]);
        let array_ptr = "/1";

        let mut array = array_original.clone();
        let array_disclosure = array.redact(array_ptr, &sd_alg)?;
        let redacted_element = array.as_array().unwrap()[1].as_object().unwrap();
        assert!(redacted_element.contains_key(&"...".to_string()));
        assert_eq!(redacted_element.len(), 1);

        array.unredact(array_disclosure, &sd_alg)?;
        assert_eq!(array, array_original);

        Ok(())
    }

    #[test]
    pub fn object_redact_unredact_round_trip() -> Result<(), Error> {
        let sd_alg = HashAlgorithmType::Sha256;

        let object_original = json!({ "a": 1, "b": 2, "c": 3 });
        let object_field = "b".to_string();
        let object_ptr = "/b";

        let mut object = object_original.clone();
        let object_disclosure = object.redact(object_ptr, &sd_alg)?;

        let map = object.as_object().unwrap();
        let redaction_list = map
            .get(&REDACTION_LIST_FIELD.to_string())
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(redaction_list.len(), 1);
        assert!(redaction_list[0].is_string());
        assert!(!map.contains_key(&object_field));

        object.unredact(object_disclosure, &sd_alg)?;
        assert_eq!(object, object_original);

        Ok(())
    }

    #[test]
    pub fn raw_data_with_disclosures() -> Result<(), Error> {
        let raw = concat!(
            "eyJhbGciOiJIUzI1NiJ9",
            ".",
            "eyJfc2QiOlsidy1VMk5xd2dTSDhQeGVLMGRVSUJIdGVMQ2ZDdW51Q3FiSFZDSGFY",
            "dlRvWSIsIm4zaGotSE1obURBQU5rdUtUcFc5V2VjM1o4bGtuUWpHajhQcDBYNXBY",
            "TmciLCJlS0p3Ni1ZSVRPa3VmanVQYVJ4TTNRNlQyMUUxLXd4NnZVTGk2eENjeWZV",
            "IiwiMS04aUowWEhCcFA3bVJNM1Y2U2Q5b3JjQ1ZWM2FHVERWeGl4U2ZhM095YyIs",
            "ImZ0MmxMbXp4SVZVcTV3TE1JYUQteUJ1RFB1b2hnYTlpYzg2aWpxckRPd1EiLCJR",
            "STlabHFIYkVSV2hGbS00Zjl3djlnSFBDYWsxNEQ4VUY5RzIwWEt1d2dVIiwibGNq",
            "cDM1OXFGWXAwZVZfOFNfOXpVMmRLR1QwLWN0bjBDZ0RJLTQ1UUVkZyIsIk4teGtt",
            "Qzh3UTczUDJqSlpSNXhGMDUtbzB5R0EtZ1cxcXByeER5Nkp5NDAiXSwiX3NkX2Fs",
            "ZyI6InNoYS0yNTYiLCJuYXRpb25hbGl0aWVzIjpbeyIuLi4iOiJMWDNqMnVNYlp0",
            "bEdKSkJFY3MwU3ZIMEZtLTJUaERvOEhNV1dqWlpkR2pZIn0seyIuLi4iOiJtV2lz",
            "alEwNjJJRVB5Wkh5aGNraEtLdVlqMm56dVY2RWExYzYxN2F5VGtrIn1dLCJzdWIi",
            "OiJ1c2VyXzQyIn0",
            ".",
            "N3Q4uR9zJle9omUpiHBJfrDLRX1o2T6O3BKLIgWBKsQ",
            "~",
            "WyJfN0ppQm9PYlM2Y0VyY2tjNy00MHFBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ",
            "~",
            "WyJjRnFvRklHMGZCSGp3TEdReXZ3M3Z3IiwiZmFtaWx5X25hbWUiLCJEb2UiXQ",
            "~",
            "WyJHMGl1bW5Mbmw2UG1RUjktYWdxXzZnIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0",
            "~",
            "WyI5aDZfcm8wd203dHRkZF9zWm5JYUp3IiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0",
            "~",
            "WyJxU19ueHR4REVwX3lVZ3dvRU9wUWtRIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIix0cnVlXQ",
            "~",
            "WyJ5dlJuWkdKU002MVhqLW9mMDNyM1BBIiwiYWRkcmVzcyIseyJjb3VudHJ5Ijoi",
            "VVMiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsInN0",
            "cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QifV0",
            "~",
            "WyJaY1N0Y1JPd1Bud1dxNWgyRVlLMHJ3IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd",
            "~",
            "WyJnVWRWaTNabWUwRFdFQ3RBUTNvWHdRIiwidXBkYXRlZF9hdCIsMTU3MDAwMDAwMF0",
            "~",
            "WyJpZHJodGlicnpzWGtROG4yVl9YTXlnIiwiVVMiXQ",
            "~",
            "WyJseDU3MnRPOG45b3NTc0k2VEpObGZRIiwiREUiXQ",
            "~",
        );

        let token: Token<Header, Value, _> = Token::parse_unverified(raw)?;

        assert_eq!(token.issuer_jwt().header().algorithm, AlgorithmType::Hs256);

        let verifier: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        let verified = token.verify_with_key(&verifier)?;
        verified.reveal()?;

        Ok(())
    }

    #[test]
    pub fn round_trip_with_disclosures() -> Result<(), Error> {
        let (issuer_priv, issuer_pub) = generate_key_pair();
        let sd_alg = HashAlgorithmType::Sha256;
        let header = Header {
            algorithm: issuer_priv.algorithm_type(),
            key_id: None,
            type_: None,
            content_type: None,
        };

        let claims = json!({
          "_sd_alg": "sha-256",
          "sub": "user_42",
          "given_name": "John",
          "family_name": "Doe",
          "email": "johndoe@example.com",
          "phone_number": "+1-202-555-0101",
          "phone_number_verified": true,
          "address": {
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "Anystate",
            "country": "US"
          },
          "birthdate": "1940-01-01",
          "updated_at": 1570000000,
          "nationalities": [
            "US",
            "DE"
          ]
        });

        let mut token: Token<Header, _, _> = Token::new(header, claims.clone(), sd_alg)?;

        token.redact("/given_name")?;
        token.redact("/family_name")?;
        token.redact("/email")?;
        token.redact("/phone_number")?;
        token.redact("/phone_number_verified")?;
        token.redact("/address")?;
        token.redact("/birthdate")?;
        token.redact("/updated_at")?;
        token.redact("/nationalities/0")?;
        token.redact("/nationalities/1")?;

        let signed_token = token.sign_with_key(&issuer_priv)?;
        let signed_token_str = signed_token.as_str();

        let recreated_token: Token<Header, Value, _> = Token::parse_unverified(signed_token_str)?;

        assert_eq!(
            signed_token.issuer_jwt().header(),
            recreated_token.issuer_jwt().header()
        );
        assert_eq!(
            signed_token.issuer_jwt().claims(),
            recreated_token.issuer_jwt().claims()
        );
        let verified_token = recreated_token.verify_with_key(&issuer_pub)?;

        let claims_parsed: Value = verified_token.reveal()?;
        assert_eq!(claims_parsed, claims);

        Ok(())
    }

    #[test]
    pub fn presentation_round_trip() -> Result<(), Error> {
        let (issuer_priv, issuer_pub) = generate_key_pair();
        let (kb_priv, kb_pub) = generate_key_pair();
        let sd_alg = HashAlgorithmType::Sha256;
        let header = Header {
            algorithm: issuer_priv.algorithm_type(),
            key_id: None,
            type_: None,
            content_type: None,
        };

        let claims = json!({
          "email": "johndoe@example.com",
          "address": {
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "Anystate",
            "country": "US"
          },
          "nationalities": [
            "US",
            "DE"
          ]
        });

        // Sign a token
        let mut token: Token<Header, _, _> = Token::new(header, claims.clone(), sd_alg)?;
        let cnf = kb_pub.jwk_thumbprint_confirmation();
        token.set_confirmation_key(cnf)?;

        token.redact("/email")?;
        token.redact("/address/street_address")?;
        token.redact("/nationalities/0")?;
        token.redact("/nationalities/1")?;

        let signed_token = token.sign_with_key(&issuer_priv)?;

        // Sign and verify a presentation over the token, with full disclosure
        {
            let preso = Presentation::new(signed_token.clone(), "audience".to_string());
            let signed_preso = preso.sign_with_key(&kb_priv)?;
            let signed_preso_str = signed_preso.as_str();

            let recreated_preso: Presentation<Header, Value, _> =
                Presentation::parse_unverified(signed_preso_str)?;

            let verified_preso = recreated_preso.verify_with_key(&kb_pub)?;
            let signed_token = verified_preso.token();
            let recreated_token = signed_token.as_unverified()?;
            let verified_token = recreated_token.verify_with_key(&issuer_pub)?;

            let _claims_parsed: Value = verified_token.reveal()?;
        }

        // Sign and verify a presentation over the token, with partial disclosure
        {
            let mut preso = Presentation::new(signed_token.clone(), "audience".to_string());
            preso.forget("/address/street_address")?;
            preso.forget("/nationalities/0")?;

            let signed_preso = preso.sign_with_key(&kb_priv)?;
            let signed_preso_str = signed_preso.as_str();

            let recreated_preso: Presentation<Header, Value, _> =
                Presentation::parse_unverified(signed_preso_str)?;

            let verified_preso = recreated_preso.verify_with_key(&kb_pub)?;
            let signed_token = verified_preso.token();
            let recreated_token = signed_token.as_unverified()?;
            let verified_token = recreated_token.verify_with_key(&issuer_pub)?;

            let _claims_parsed: Value = verified_token.reveal()?;
        }

        // Sign and verify a presentation over the token, with no disclosure
        {
            let mut preso = Presentation::new(signed_token.clone(), "audience".to_string());
            preso.forget_all()?;

            let signed_preso = preso.sign_with_key(&kb_priv)?;
            let signed_preso_str = signed_preso.as_str();

            let recreated_preso: Presentation<Header, Value, _> =
                Presentation::parse_unverified(signed_preso_str)?;

            let verified_preso = recreated_preso.verify_with_key(&kb_pub)?;
            let signed_token = verified_preso.token();
            let recreated_token = signed_token.as_unverified()?;
            let verified_token = recreated_token.verify_with_key(&issuer_pub)?;

            let _claims_parsed: Value = verified_token.reveal()?;
        }

        Ok(())
    }
}
