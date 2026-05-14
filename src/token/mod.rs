//! A structured representation of a JWT.

pub mod signed;
pub mod verified;

#[derive(Clone)]
pub struct Unsigned;

#[derive(Clone)]
pub struct Signed {
    pub token_string: String,
}

#[derive(Clone)]
pub struct Verified;

#[derive(Clone)]
pub struct Unverified<'a> {
    pub header_str: &'a str,
    pub claims_str: &'a str,
    pub signature_str: &'a str,
}
