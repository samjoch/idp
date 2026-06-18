//! RSA key generation, JWT signing material, and small encoding helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// base64url-encode without padding (the encoding used throughout JOSE/OIDC).
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a fresh 2048-bit RSA private key as a PKCS#8 PEM string.
pub fn generate_private_pem() -> String {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
    key.to_pkcs8_pem(LineEnding::LF)
        .expect("failed to encode private key")
        .to_string()
}

/// A random key id, used in the JWT header and JWKS.
pub fn random_kid() -> String {
    b64url(&rand::random::<[u8; 12]>())
}

/// The JWKS public components (base64url) derived from a private key PEM.
pub struct PublicParts {
    pub n: String,
    pub e: String,
}

pub fn public_parts(private_pem: &str) -> PublicParts {
    let private = RsaPrivateKey::from_pkcs8_pem(private_pem).expect("invalid stored private key");
    let public = private.to_public_key();
    PublicParts {
        n: b64url(&public.n().to_bytes_be()),
        e: b64url(&public.e().to_bytes_be()),
    }
}

pub fn encoding_key(private_pem: &str) -> EncodingKey {
    EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("invalid private key for signing")
}

pub fn decoding_key(parts: &PublicParts) -> DecodingKey {
    DecodingKey::from_rsa_components(&parts.n, &parts.e).expect("invalid public key components")
}

/// A URL-safe random token (used for auth codes, refresh tokens, secrets).
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::Rng::fill(&mut rand::thread_rng(), buf.as_mut_slice());
    b64url(&buf)
}

/// Verify a PKCE code_verifier against a stored challenge.
pub fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            b64url(&digest) == challenge
        }
        "plain" => verifier == challenge,
        _ => false,
    }
}
