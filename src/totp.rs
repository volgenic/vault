//! 2FA codes (TOTP, RFC 6238). The seed never leaves; only the current code does (R5, R6).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::VaultError;
use crate::secret::SecretValue;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpParams {
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl Default for TotpParams {
    fn default() -> Self {
        TotpParams { algorithm: Algorithm::Sha1, digits: 6, period: 30 }
    }
}

/// The current code and how many seconds it has left.
#[derive(Serialize, Clone, Debug)]
pub struct TotpCode {
    pub code: String,
    pub seconds_left: u64,
}

/// Reads what the person pasted into `vault add --kind 2fa`: a base32 seed, or an
/// `otpauth://totp/...` link from a QR code. Returns the raw seed and its parameters.
/// This is the "reading a 2FA seed" call site of `expose` in R1.
pub fn parse_seed_input(input: &SecretValue) -> Result<(SecretValue, TotpParams), VaultError> {
    let text = std::str::from_utf8(input.expose())
        .map_err(|_| VaultError::InvalidSecret("the seed isn't text".into()))?
        .trim();
    if text.to_ascii_lowercase().starts_with("otpauth://") {
        parse_otpauth(text)
    } else {
        Ok((decode_base32(text)?, TotpParams::default()))
    }
}

fn parse_otpauth(text: &str) -> Result<(SecretValue, TotpParams), VaultError> {
    let bad = |why: &str| VaultError::InvalidSecret(format!("otpauth link: {why}"));
    let url = url::Url::parse(text).map_err(|_| bad("not a valid link"))?;
    if url.host_str() != Some("totp") {
        return Err(bad("only totp links are supported"));
    }
    let mut params = TotpParams::default();
    let mut seed = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => seed = Some(decode_base32(&value)?),
            "algorithm" => {
                params.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(bad("unknown algorithm")),
                }
            }
            "digits" => {
                params.digits = value.parse().map_err(|_| bad("bad digits"))?;
                if !(6..=8).contains(&params.digits) {
                    return Err(bad("digits must be 6 to 8"));
                }
            }
            "period" => {
                params.period = value.parse().map_err(|_| bad("bad period"))?;
                if !(10..=300).contains(&params.period) {
                    return Err(bad("period must be 10 to 300 seconds"));
                }
            }
            _ => {}
        }
    }
    let seed = seed.ok_or_else(|| bad("no secret= in the link"))?;
    Ok((seed, params))
}

fn decode_base32(text: &str) -> Result<SecretValue, VaultError> {
    let mut cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let decoded = data_encoding::BASE32_NOPAD.decode(cleaned.as_bytes());
    cleaned.zeroize();
    let bytes = decoded.map_err(|_| VaultError::InvalidSecret("the seed isn't valid base32".into()))?;
    if bytes.len() < 10 {
        let mut bytes = bytes;
        bytes.zeroize();
        return Err(VaultError::InvalidSecret("the seed is too short (under 80 bits)".into()));
    }
    Ok(SecretValue::from_vec(bytes))
}

/// The code for `now` (Unix seconds, from the vault's own clock; callers can't choose it: R6).
/// This is the "computing a 2FA code" call site of `expose` in R1.
pub fn code_at(seed: &SecretValue, params: TotpParams, now: u64) -> Result<TotpCode, VaultError> {
    let counter = (now / params.period).to_be_bytes();
    let mut digest = match params.algorithm {
        Algorithm::Sha1 => hmac_bytes::<Hmac<sha1::Sha1>>(seed, &counter)?,
        Algorithm::Sha256 => hmac_bytes::<Hmac<sha2::Sha256>>(seed, &counter)?,
        Algorithm::Sha512 => hmac_bytes::<Hmac<sha2::Sha512>>(seed, &counter)?,
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    digest.zeroize();
    let modulus = 10u64.pow(params.digits);
    let code = format!("{:0width$}", u64::from(binary) % modulus, width = params.digits as usize);
    Ok(TotpCode { code, seconds_left: params.period - now % params.period })
}

fn hmac_bytes<M: Mac + hmac::digest::KeyInit>(seed: &SecretValue, message: &[u8]) -> Result<Vec<u8>, VaultError> {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(seed.expose())
        .map_err(|_| VaultError::InvalidSecret("bad seed".into()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}
