#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use napi::{Error, Result};
use napi_derive::napi;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[napi(object)]
pub struct AesGcmEnvelope {
    pub iv_b64: String,
    pub tag_b64: String,
    pub ct_b64: String,
}

fn decode_fixed<const N: usize>(hex_value: &str, label: &str) -> Result<[u8; N]> {
    let decoded = hex::decode(hex_value).map_err(|_| Error::from_reason(format!("Invalid {label} hex")))?;
    if decoded.len() != N {
        return Err(Error::from_reason(format!("Invalid {label} length")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn decode_hex(hex_value: &str, label: &str) -> Result<Vec<u8>> {
    hex::decode(hex_value).map_err(|_| Error::from_reason(format!("Invalid {label} hex")))
}

fn decode_b64(value: &str, label: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD
        .decode(value)
        .map_err(|_| Error::from_reason(format!("Invalid {label} base64")))
}

fn encode_b64(value: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(value)
}

fn random_fixed<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

fn box1_aad(ephemeral_public: &[u8; 32], nonce: &[u8; 24]) -> Vec<u8> {
    format!(
        "voryx:box1:v1:{}:{}",
        hex::encode(ephemeral_public),
        hex::encode(nonce)
    )
    .into_bytes()
}

fn box1_encrypt(plaintext: &[u8], recipient_public: &[u8; 32]) -> Result<String> {
    let ephemeral_secret = Zeroizing::new(random_fixed::<32>());
    let ephemeral_public = MontgomeryPoint::mul_base_clamped(*ephemeral_secret).to_bytes();
    let shared_secret = Zeroizing::new(MontgomeryPoint(*recipient_public).mul_clamped(*ephemeral_secret).to_bytes());
    let nonce = random_fixed::<24>();
    let hkdf = Hkdf::<Sha256>::new(Some(&nonce), &*shared_secret);
    let mut aes_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"voryx:box1:aes256gcm:key:v1", &mut *aes_key)
        .map_err(|_| Error::from_reason("HKDF expand failed".to_string()))?;
    let aad = box1_aad(&ephemeral_public, &nonce);
    let cipher = Aes256Gcm::new_from_slice(&*aes_key)
        .map_err(|_| Error::from_reason("Invalid AES key".to_string()))?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce[..12]),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::from_reason("box1 encrypt failed".to_string()))?;
    Ok(format!(
        "box1:{}:{}:{}",
        hex::encode(ephemeral_public),
        hex::encode(nonce),
        hex::encode(sealed)
    ))
}

#[napi]
pub fn sign_ed25519(data: String, private_key_hex: String) -> Result<String> {
    if private_key_hex.len() < 64 {
        return Err(Error::from_reason("Invalid private key length".to_string()));
    }
    let secret = Zeroizing::new(decode_fixed::<32>(&private_key_hex[0..64], "private key")?);
    let signing_key = SigningKey::from_bytes(&secret);
    let signature = signing_key.sign(data.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

#[napi(object)]
pub struct Ed25519KeyPair {
    pub public_key_hex: String,
    pub private_key_hex: String,
}

#[napi]
pub fn generate_ed25519_key_pair() -> Result<Ed25519KeyPair> {
    let secret = Zeroizing::new(random_fixed::<32>());
    let signing_key = SigningKey::from_bytes(&secret);
    let verify_key = signing_key.verifying_key();
    let public_key = verify_key.to_bytes();
    let mut private_key = Zeroizing::new([0u8; 64]);
    private_key[..32].copy_from_slice(&*secret);
    private_key[32..].copy_from_slice(&public_key);
    Ok(Ed25519KeyPair {
        public_key_hex: hex::encode(public_key),
        private_key_hex: hex::encode(&*private_key),
    })
}

#[napi]
pub fn seal_box1(plaintext_b64: String, recipient_public_hex: String) -> Result<String> {
    let plaintext = Zeroizing::new(decode_b64(&plaintext_b64, "plaintext")?);
    let recipient_public = decode_fixed::<32>(&recipient_public_hex, "recipient public key")?;
    box1_encrypt(&plaintext, &recipient_public)
}

#[napi]
pub fn verify_ed25519(data: String, signature_hex: String, public_key_hex: String) -> Result<bool> {
    let signature_bytes = decode_fixed::<64>(&signature_hex, "signature")?;
    let public_key_bytes = decode_fixed::<32>(&public_key_hex, "public key")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| Error::from_reason("Invalid public key".to_string()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    Ok(verifying_key.verify(data.as_bytes(), &signature).is_ok())
}

#[napi]
pub fn canonical_auth_payload_v1(
    ts: f64,
    nonce: String,
    method: String,
    path: String,
    body_hash: String,
    key_id: String,
    public_key: String,
) -> Result<String> {
    let ts = ts.floor() as i64;
    let m = method.trim().to_uppercase();
    let p = if path.trim().is_empty() { "/".to_string() } else { path.trim().to_string() };
    if [nonce.as_str(), m.as_str(), p.as_str(), body_hash.as_str(), key_id.as_str(), public_key.as_str()]
        .iter()
        .any(|f| f.contains('|'))
    {
        return Err(Error::from_reason(
            "Canonical payload fields must not contain pipe".to_string(),
        ));
    }
    Ok(format!(
        "voryx-auth-v1|{}|{}|{}|{}|{}|{}|{}",
        ts,
        nonce.trim(),
        m,
        p,
        body_hash.trim(),
        key_id.trim(),
        public_key.trim()
    ))
}

#[napi]
pub fn canonical_ws_subscribe_payload_v1(
    ts: f64,
    nonce: String,
    session_id: String,
    key_id: String,
) -> Result<String> {
    let ts = ts.floor() as i64;
    if [nonce.as_str(), session_id.as_str(), key_id.as_str()]
        .iter()
        .any(|f| f.contains('|'))
    {
        return Err(Error::from_reason(
            "Canonical payload fields must not contain pipe".to_string(),
        ));
    }
    Ok(format!(
        "voryx-ws-auth-v1|{}|{}|subscribe|{}|{}",
        ts,
        nonce.trim(),
        session_id.trim(),
        key_id.trim()
    ))
}

#[napi]
pub fn hkdf_sha256_hex(ikm_hex: String, len: u32, salt_hex: Option<String>, info_hex: Option<String>) -> Result<String> {
    let ikm = Zeroizing::new(decode_hex(&ikm_hex, "ikm")?);
    if ikm.is_empty() {
        return Err(Error::from_reason("IKM must not be empty".to_string()));
    }
    if len == 0 || len > 1024 {
        return Err(Error::from_reason("HKDF output length out of range".to_string()));
    }
    let salt = match salt_hex {
        Some(value) if !value.trim().is_empty() => Some(Zeroizing::new(decode_hex(value.trim(), "salt")?)),
        _ => None,
    };
    let info = Zeroizing::new(match info_hex {
        Some(value) if !value.trim().is_empty() => decode_hex(value.trim(), "info")?,
        _ => Vec::new(),
    });
    let hk = Hkdf::<Sha256>::new(salt.as_deref().map(|v| &**v), &ikm);
    let mut out = Zeroizing::new(vec![0u8; len as usize]);
    hk.expand(&info, &mut out)
        .map_err(|_| Error::from_reason("HKDF expand failed".to_string()))?;
    Ok(hex::encode(out))
}

#[napi]
pub fn aes256gcm_encrypt(key_hex: String, plaintext_b64: String, aad_b64: Option<String>) -> Result<AesGcmEnvelope> {
    let key = Zeroizing::new(decode_fixed::<32>(&key_hex, "AES-256 key")?);
    let plaintext = Zeroizing::new(decode_b64(&plaintext_b64, "plaintext")?);
    let aad = Zeroizing::new(match aad_b64 {
        Some(value) if !value.trim().is_empty() => decode_b64(value.trim(), "aad")?,
        _ => Vec::new(),
    });
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| Error::from_reason("Invalid AES key".to_string()))?;
    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(&iv), payload)
        .map_err(|_| Error::from_reason("AES-GCM encrypt failed".to_string()))?;
    if sealed.len() < 16 {
        return Err(Error::from_reason("AES-GCM output is malformed".to_string()));
    }
    let tag = sealed.split_off(sealed.len() - 16);
    Ok(AesGcmEnvelope {
        iv_b64: encode_b64(&iv),
        tag_b64: encode_b64(&tag),
        ct_b64: encode_b64(&sealed),
    })
}

#[napi]
pub fn aes256gcm_decrypt(
    key_hex: String,
    iv_b64: String,
    tag_b64: String,
    ct_b64: String,
    aad_b64: Option<String>,
) -> Result<String> {
    let key = Zeroizing::new(decode_fixed::<32>(&key_hex, "AES-256 key")?);
    let iv = Zeroizing::new(decode_b64(&iv_b64, "iv")?);
    if iv.len() != 12 {
        return Err(Error::from_reason("Invalid AES-GCM nonce length".to_string()));
    }
    let tag = Zeroizing::new(decode_b64(&tag_b64, "tag")?);
    if tag.len() != 16 {
        return Err(Error::from_reason("Invalid AES-GCM tag length".to_string()));
    }
    let mut ct = Zeroizing::new(decode_b64(&ct_b64, "ciphertext")?);
    if ct.is_empty() {
        return Err(Error::from_reason("Ciphertext must not be empty".to_string()));
    }
    let aad = Zeroizing::new(match aad_b64 {
        Some(value) if !value.trim().is_empty() => decode_b64(value.trim(), "aad")?,
        _ => Vec::new(),
    });
    ct.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| Error::from_reason("Invalid AES key".to_string()))?;
    let payload = Payload { msg: &ct, aad: &aad };
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), payload)
        .map_err(|_| Error::from_reason("AES-GCM auth failed".to_string()))?;
    Ok(encode_b64(&plain))
}

#[napi]
pub fn random_bytes_hex(len: u32) -> Result<String> {
    if len == 0 || len > 4096 {
        return Err(Error::from_reason("random length out of range".to_string()));
    }
    let mut out = vec![0u8; len as usize];
    OsRng.fill_bytes(&mut out);
    Ok(hex::encode(out))
}

#[napi]
pub fn constant_time_eq_hex(left_hex: String, right_hex: String) -> Result<bool> {
    let left = decode_hex(&left_hex, "left")?;
    let right = decode_hex(&right_hex, "right")?;
    if left.len() != right.len() {
        return Ok(false);
    }
    Ok(bool::from(left.ct_eq(&right)))
}

#[napi]
pub fn sha256_hex(data: String) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[napi]
pub fn sha256_hex_from_b64(data_b64: String) -> Result<String> {
    let decoded = decode_b64(&data_b64, "sha256 input")?;
    let mut hasher = Sha256::new();
    hasher.update(&decoded);
    Ok(hex::encode(hasher.finalize()))
}

#[napi]
pub fn derive_opaque_index(
    scope: String,
    part_a: String,
    part_b: Option<String>,
    part_c: Option<String>,
    part_d: Option<String>,
) -> Result<String> {
    let normalized_scope = scope.trim();
    if normalized_scope.is_empty() {
        return Err(Error::from_reason("Opaque index scope is required".to_string()));
    }
    let mut parts = vec![part_a.trim().to_string()];
    if let Some(value) = part_b {
        parts.push(value.trim().to_string());
    }
    if let Some(value) = part_c {
        parts.push(value.trim().to_string());
    }
    if let Some(value) = part_d {
        parts.push(value.trim().to_string());
    }
    let payload = format!("{}:{}", normalized_scope, parts.join(":"));
    sha256_hex(payload)
}

#[napi]
pub fn derive_commitment(
    label: String,
    subject: String,
    witness: Option<String>,
    context: Option<String>,
) -> Result<String> {
    let normalized_label = label.trim();
    if normalized_label.is_empty() {
        return Err(Error::from_reason("Commitment label is required".to_string()));
    }
    let mut parts = vec![subject.trim().to_string()];
    if let Some(value) = witness {
        parts.push(value.trim().to_string());
    }
    if let Some(value) = context {
        parts.push(value.trim().to_string());
    }
    sha256_hex(format!("{}:{}", normalized_label, parts.join(":")))
}

#[napi]
pub fn derive_nullifier(seed: String, context: Option<String>) -> Result<String> {
    let normalized_seed = seed.trim();
    if normalized_seed.is_empty() {
        return Err(Error::from_reason("Nullifier seed is required".to_string()));
    }
    let payload = match context {
        Some(value) => format!("{}:{}", normalized_seed, value.trim()),
        None => normalized_seed.to_string(),
    };
    sha256_hex(payload)
}

#[napi]
pub fn derive_proof_hash(left: String, right: String, context: Option<String>) -> Result<String> {
    let normalized_left = left.trim();
    let normalized_right = right.trim();
    if normalized_left.is_empty() || normalized_right.is_empty() {
        return Err(Error::from_reason("Proof hash inputs are required".to_string()));
    }
    let payload = match context {
        Some(value) => format!("{}:{}:{}", normalized_left, normalized_right, value.trim()),
        None => format!("{}:{}", normalized_left, normalized_right),
    };
    sha256_hex(payload)
}
