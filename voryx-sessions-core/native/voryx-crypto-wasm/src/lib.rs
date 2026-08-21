#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use js_sys::{Object, Reflect};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn decode_hex(input: &str, label: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(input).map_err(|_| JsValue::from_str(&format!("Invalid {} hex", label)))
}

fn decode_b64(input: &str, label: &str) -> Result<Vec<u8>, JsValue> {
    B64.decode(input)
        .map_err(|_| JsValue::from_str(&format!("Invalid {} base64", label)))
}

fn decode_fixed<const N: usize>(input: &str, label: &str) -> Result<[u8; N], JsValue> {
    let decoded = decode_hex(input, label)?;
    if decoded.len() != N {
        return Err(JsValue::from_str(&format!("Invalid {} length", label)));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn random_fixed<const N: usize>() -> Result<[u8; N], JsValue> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|_| JsValue::from_str("Failed to gather randomness"))?;
    Ok(out)
}

fn hmac_sha512_raw(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key)
        .map_err(|_| JsValue::from_str("Invalid HMAC key"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn derive_ratchet_step(chain: &[u8]) -> Result<(Vec<u8>, Vec<u8>), JsValue> {
    if chain.len() != 32 {
        return Err(JsValue::from_str("Ratchet chain must be 32 bytes"));
    }
    let mk = hmac_sha512_raw(chain, b"voryx:v8r:mk")?;
    let ck = hmac_sha512_raw(chain, b"voryx:v8r:ck")?;
    Ok((mk[..32].to_vec(), ck[..32].to_vec()))
}

#[wasm_bindgen(js_name = signEd25519)]
pub fn sign_ed25519(data: String, private_key_hex: String) -> Result<String, JsValue> {
    if private_key_hex.len() < 64 {
        return Err(JsValue::from_str("Invalid private key length"));
    }
    let secret = Zeroizing::new(decode_fixed::<32>(&private_key_hex[0..64], "private key")?);
    let signing_key = SigningKey::from_bytes(&secret);
    let signature = signing_key.sign(data.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

#[wasm_bindgen(js_name = verifyEd25519)]
pub fn verify_ed25519(data: String, signature_hex: String, public_key_hex: String) -> Result<bool, JsValue> {
    let signature_bytes = decode_fixed::<64>(&signature_hex, "signature")?;
    let public_key_bytes = decode_fixed::<32>(&public_key_hex, "public key")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| JsValue::from_str("Invalid public key"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    Ok(verifying_key.verify(data.as_bytes(), &signature).is_ok())
}

#[wasm_bindgen(js_name = generateClientKeyMaterial)]
pub fn generate_client_key_material() -> Result<JsValue, JsValue> {
    let sign_seed = Zeroizing::new(random_fixed::<32>()?);
    let signing_key = SigningKey::from_bytes(&sign_seed);
    let verify_key = signing_key.verifying_key();
    let sign_secret = Zeroizing::new(signing_key.to_keypair_bytes());

    let kx_private = Zeroizing::new(random_fixed::<32>()?);
    let kx_public = MontgomeryPoint::mul_base_clamped(*kx_private).to_bytes();

    let public_key_hex = hex::encode(verify_key.to_bytes());
    let private_key_hex = hex::encode(&*sign_secret);
    let kx_public_hex = hex::encode(kx_public);
    let kx_private_hex = hex::encode(&*kx_private);

    let out = Object::new();
    Reflect::set(&out, &JsValue::from_str("publicKey"), &JsValue::from_str(&public_key_hex))?;
    Reflect::set(&out, &JsValue::from_str("privateKey"), &JsValue::from_str(&private_key_hex))?;
    Reflect::set(&out, &JsValue::from_str("kxPublicKey"), &JsValue::from_str(&kx_public_hex))?;
    Reflect::set(&out, &JsValue::from_str("kxPrivateKey"), &JsValue::from_str(&kx_private_hex))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = sealBox1)]
pub fn seal_box1(plaintext_utf8: String, recipient_public_hex: String) -> Result<JsValue, JsValue> {
    let recipient_public = decode_fixed::<32>(&recipient_public_hex, "recipient public key")?;
    let eph_private = Zeroizing::new(random_fixed::<32>()?);
    let eph_public = MontgomeryPoint::mul_base_clamped(*eph_private).to_bytes();
    let shared = Zeroizing::new(MontgomeryPoint(recipient_public).mul_clamped(*eph_private).to_bytes());
    let nonce = random_fixed::<24>()?;
    let mut hkdf_out = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&nonce), &*shared);
    hk.expand(b"voryx:box1:aes256gcm:key:v1", &mut hkdf_out)
        .map_err(|_| JsValue::from_str("Failed to derive box1 key"))?;

    let aad = format!("voryx:box1:v1:{}:{}", hex::encode(eph_public), hex::encode(nonce));
    let cipher = Aes256Gcm::new_from_slice(&hkdf_out).map_err(|_| JsValue::from_str("Invalid box1 key"))?;
    let plaintext = Zeroizing::new(plaintext_utf8.into_bytes());
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce[..12]),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| JsValue::from_str("Box1 encryption failed"))?;

    let out = Object::new();
    Reflect::set(&out, &JsValue::from_str("ephemeralPublicKeyHex"), &JsValue::from_str(&hex::encode(eph_public)))?;
    Reflect::set(&out, &JsValue::from_str("nonceHex"), &JsValue::from_str(&hex::encode(nonce)))?;
    Reflect::set(&out, &JsValue::from_str("cipherHex"), &JsValue::from_str(&hex::encode(sealed)))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = openBox1)]
pub fn open_box1(
    ephemeral_public_hex: String,
    nonce_hex: String,
    cipher_hex: String,
    recipient_private_hex: String,
) -> Result<String, JsValue> {
    let eph_public = decode_fixed::<32>(&ephemeral_public_hex, "ephemeral public key")?;
    let nonce = decode_fixed::<24>(&nonce_hex, "nonce")?;
    let cipher_text = Zeroizing::new(decode_hex(&cipher_hex, "ciphertext")?);
    if cipher_text.len() <= 16 {
        return Err(JsValue::from_str("Invalid box1 ciphertext"));
    }
    let recipient_private = Zeroizing::new(decode_fixed::<32>(&recipient_private_hex, "recipient private key")?);
    let shared = Zeroizing::new(MontgomeryPoint(eph_public).mul_clamped(*recipient_private).to_bytes());
    let mut hkdf_out = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&nonce), &*shared);
    hk.expand(b"voryx:box1:aes256gcm:key:v1", &mut hkdf_out)
        .map_err(|_| JsValue::from_str("Failed to derive box1 key"))?;

    let aad = format!("voryx:box1:v1:{}:{}", ephemeral_public_hex.trim().to_lowercase(), nonce_hex.trim().to_lowercase());
    let cipher = Aes256Gcm::new_from_slice(&hkdf_out).map_err(|_| JsValue::from_str("Invalid box1 key"))?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce[..12]),
            Payload {
                msg: &cipher_text,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| JsValue::from_str("Box1 decryption failed"))?;
    String::from_utf8(plain).map_err(|_| JsValue::from_str("Box1 plaintext is not utf8"))
}

#[derive(Serialize, Deserialize)]
struct StoredRatchetState {
    counter: u32,
    #[serde(rename = "chainB64")]
    chain_b64: String,
}

#[wasm_bindgen(js_name = pbkdf2Sha256Hex)]
pub fn pbkdf2_sha256_hex(password: String, salt: String, iterations: u32, dk_len: u32) -> Result<String, JsValue> {
    if iterations == 0 || dk_len == 0 || dk_len > 1024 {
        return Err(JsValue::from_str("PBKDF2 parameter out of range"));
    }
    let mut out = Zeroizing::new(vec![0u8; dk_len as usize]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations, &mut out);
    Ok(hex::encode(out))
}

#[wasm_bindgen(js_name = pbkdf2Sha512Hex)]
pub fn pbkdf2_sha512_hex(password: String, salt: String, iterations: u32, dk_len: u32) -> Result<String, JsValue> {
    if iterations == 0 || dk_len == 0 || dk_len > 1024 {
        return Err(JsValue::from_str("PBKDF2 parameter out of range"));
    }
    let mut out = Zeroizing::new(vec![0u8; dk_len as usize]);
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt.as_bytes(), iterations, &mut out);
    Ok(hex::encode(out))
}

#[wasm_bindgen(js_name = sha256Hex)]
pub fn sha256_hex(data: String) -> Result<String, JsValue> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[wasm_bindgen(js_name = sha256HexFromB64)]
pub fn sha256_hex_from_b64(data_b64: String) -> Result<String, JsValue> {
    use sha2::Digest;
    let decoded = decode_b64(&data_b64, "sha256 input")?;
    let mut hasher = Sha256::new();
    hasher.update(&decoded);
    Ok(hex::encode(hasher.finalize()))
}

#[wasm_bindgen(js_name = hmacSha512Hex)]
pub fn hmac_sha512_hex(key_hex: String, data: String) -> Result<String, JsValue> {
    let key = Zeroizing::new(decode_hex(&key_hex, "key")?);
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&key)
        .map_err(|_| JsValue::from_str("Invalid HMAC key"))?;
    mac.update(data.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[wasm_bindgen(js_name = canonicalAuthPayloadV1)]
pub fn canonical_auth_payload_v1(
    ts: u64,
    nonce: String,
    method: String,
    path: String,
    body_hash: String,
    key_id: String,
    public_key: String,
) -> Result<String, JsValue> {
    let m = method.trim().to_uppercase();
    let p = if path.trim().is_empty() { "/".to_string() } else { path.trim().to_string() };
    let fields = [&nonce, &m, &p, &body_hash, &key_id, &public_key];
    if fields.iter().any(|f| f.contains('|')) {
        return Err(JsValue::from_str("Canonical payload fields must not contain pipe"));
    }
    Ok(format!(
        "voryx-auth-v1|{}|{}|{}|{}|{}|{}|{}",
        ts, nonce.trim(), m, p, body_hash.trim(), key_id.trim(), public_key.trim()
    ))
}

#[wasm_bindgen(js_name = canonicalWsSubscribePayloadV1)]
pub fn canonical_ws_subscribe_payload_v1(
    ts: u64,
    nonce: String,
    session_id: String,
    key_id: String,
) -> Result<String, JsValue> {
    let fields = [&nonce, &session_id, &key_id];
    if fields.iter().any(|f| f.contains('|')) {
        return Err(JsValue::from_str("Canonical payload fields must not contain pipe"));
    }
    Ok(format!(
        "voryx-ws-auth-v1|{}|{}|subscribe|{}|{}",
        ts,
        nonce.trim(),
        session_id.trim(),
        key_id.trim()
    ))
}

#[wasm_bindgen(js_name = ratchetStepState)]
pub fn ratchet_step_state(chain_hex: String, counter: u32) -> Result<JsValue, JsValue> {
    let chain = decode_hex(&chain_hex, "ratchet chain")?;
    let (mk, next_chain) = derive_ratchet_step(&chain)?;
    let out = Object::new();
    Reflect::set(&out, &JsValue::from_str("messageKeyHex"), &JsValue::from_str(&hex::encode(mk)))?;
    Reflect::set(&out, &JsValue::from_str("nextChainHex"), &JsValue::from_str(&hex::encode(next_chain)))?;
    Reflect::set(&out, &JsValue::from_str("nextCounter"), &JsValue::from_f64((counter + 1) as f64))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = ratchetReceiveTransition)]
pub fn ratchet_receive_transition(
    chain_hex: String,
    current_counter: u32,
    incoming_counter: u32,
) -> Result<JsValue, JsValue> {
    if incoming_counter < current_counter {
        return Err(JsValue::from_str("Replay or stale ratchet counter"));
    }
    let mut chain = Zeroizing::new(decode_hex(&chain_hex, "ratchet chain")?);
    if chain.len() != 32 {
        return Err(JsValue::from_str("Ratchet chain must be 32 bytes"));
    }
    let mut cursor = current_counter;
    while cursor < incoming_counter {
        let (_, next_chain) = derive_ratchet_step(&chain)?;
        chain = Zeroizing::new(next_chain);
        cursor += 1;
    }
    let (mk, next_chain) = derive_ratchet_step(&chain)?;
    let out = Object::new();
    Reflect::set(&out, &JsValue::from_str("messageKeyHex"), &JsValue::from_str(&hex::encode(mk)))?;
    Reflect::set(&out, &JsValue::from_str("nextChainHex"), &JsValue::from_str(&hex::encode(next_chain)))?;
    Reflect::set(&out, &JsValue::from_str("newCounter"), &JsValue::from_f64((incoming_counter + 1) as f64))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = aes256GcmEncrypt)]
pub fn aes256_gcm_encrypt(key_hex: String, plaintext_b64: String, aad_b64: Option<String>) -> Result<JsValue, JsValue> {
    let key = Zeroizing::new(decode_hex(&key_hex, "AES key")?);
    if key.len() != 32 {
        return Err(JsValue::from_str("AES-256 key must be 32 bytes"));
    }
    let plaintext = Zeroizing::new(decode_b64(&plaintext_b64, "plaintext")?);
    let aad = Zeroizing::new(match aad_b64 {
        Some(v) if !v.trim().is_empty() => decode_b64(v.trim(), "aad")?,
        _ => Vec::new(),
    });
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|_| JsValue::from_str("Failed to gather randomness"))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| JsValue::from_str("Invalid AES key"))?;
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| JsValue::from_str("AES-GCM encrypt failed"))?;
    if sealed.len() < 16 {
        return Err(JsValue::from_str("Malformed AES-GCM output"));
    }
    let tag = sealed.split_off(sealed.len() - 16);
    let out = Object::new();
    Reflect::set(&out, &JsValue::from_str("ivB64"), &JsValue::from_str(&B64.encode(iv)))?;
    Reflect::set(&out, &JsValue::from_str("tagB64"), &JsValue::from_str(&B64.encode(tag)))?;
    Reflect::set(&out, &JsValue::from_str("ctB64"), &JsValue::from_str(&B64.encode(sealed)))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = aes256GcmDecrypt)]
pub fn aes256_gcm_decrypt(
    key_hex: String,
    iv_b64: String,
    tag_b64: String,
    ct_b64: String,
    aad_b64: Option<String>,
) -> Result<String, JsValue> {
    let key = Zeroizing::new(decode_hex(&key_hex, "AES key")?);
    if key.len() != 32 {
        return Err(JsValue::from_str("AES-256 key must be 32 bytes"));
    }
    let iv = decode_b64(&iv_b64, "iv")?;
    if iv.len() != 12 {
        return Err(JsValue::from_str("AES-GCM nonce must be 12 bytes"));
    }
    let tag = Zeroizing::new(decode_b64(&tag_b64, "tag")?);
    if tag.len() != 16 {
        return Err(JsValue::from_str("AES-GCM tag must be 16 bytes"));
    }
    let mut ct = Zeroizing::new(decode_b64(&ct_b64, "ciphertext")?);
    if ct.is_empty() {
        return Err(JsValue::from_str("Ciphertext must not be empty"));
    }
    let aad = Zeroizing::new(match aad_b64 {
        Some(v) if !v.trim().is_empty() => decode_b64(v.trim(), "aad")?,
        _ => Vec::new(),
    });
    ct.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| JsValue::from_str("Invalid AES key"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: &aad })
        .map_err(|_| JsValue::from_str("AES-GCM auth failed"))?;
    Ok(B64.encode(plain))
}

#[wasm_bindgen(js_name = ratchetStateSeal)]
pub fn ratchet_state_seal(
    key_hex: String,
    aad_utf8: String,
    counter: u32,
    chain_b64: String,
) -> Result<String, JsValue> {
    let state = StoredRatchetState { counter, chain_b64 };
    let plain = Zeroizing::new(serde_json::to_vec(&state).map_err(|_| JsValue::from_str("Failed to encode ratchet state"))?);
    let key = Zeroizing::new(decode_hex(&key_hex, "AES key")?);
    if key.len() != 32 {
        return Err(JsValue::from_str("AES-256 key must be 32 bytes"));
    }
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|_| JsValue::from_str("Failed to gather randomness"))?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| JsValue::from_str("Invalid AES key"))?;
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: &plain, aad: aad_utf8.as_bytes() })
        .map_err(|_| JsValue::from_str("AES-GCM encrypt failed"))?;
    if sealed.len() < 16 {
        return Err(JsValue::from_str("Malformed AES-GCM output"));
    }
    let tag = sealed.split_off(sealed.len() - 16);
    let mut ct_with_tag = sealed;
    ct_with_tag.extend_from_slice(&tag);
    Ok(format!("v2:{}:{}", B64.encode(iv), B64.encode(ct_with_tag)))
}

#[wasm_bindgen(js_name = ratchetStateOpen)]
pub fn ratchet_state_open(
    key_hex: String,
    aad_utf8: String,
    payload: String,
) -> Result<JsValue, JsValue> {
    let parts: Vec<&str> = payload.split(':').collect();
    if parts.len() != 3 || parts[0] != "v2" {
        return Err(JsValue::from_str("Invalid ratchet state envelope version"));
    }
    let iv = decode_b64(parts[1], "iv")?;
    if iv.len() != 12 {
        return Err(JsValue::from_str("Invalid ratchet state iv"));
    }
    let ct_with_tag = Zeroizing::new(decode_b64(parts[2], "ciphertext")?);
    if ct_with_tag.len() <= 16 {
        return Err(JsValue::from_str("Invalid ratchet state ciphertext"));
    }
    let key = Zeroizing::new(decode_hex(&key_hex, "AES key")?);
    if key.len() != 32 {
        return Err(JsValue::from_str("AES-256 key must be 32 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| JsValue::from_str("Invalid AES key"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct_with_tag, aad: aad_utf8.as_bytes() })
        .map_err(|_| JsValue::from_str("AES-GCM auth failed"))?;
    let decoded: StoredRatchetState =
        serde_json::from_slice(&plain).map_err(|_| JsValue::from_str("Invalid ratchet state payload"))?;
    let out = Object::new();
    Reflect::set(&out, &JsValue::from_str("counter"), &JsValue::from_f64(decoded.counter as f64))?;
    Reflect::set(&out, &JsValue::from_str("chainB64"), &JsValue::from_str(&decoded.chain_b64))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = argon2idHex)]
pub fn argon2id_hex(
    password: String,
    salt: String,
    dk_len: u32,
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<String, JsValue> {
    if dk_len == 0 || dk_len > 1024 {
        return Err(JsValue::from_str("Argon2 output length out of range"));
    }
    let params = Params::new(memory_kib, time_cost, parallelism, Some(dk_len as usize))
        .map_err(|_| JsValue::from_str("Invalid Argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new(vec![0u8; dk_len as usize]);
    argon
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out)
        .map_err(|_| JsValue::from_str("Argon2id hashing failed"))?;
    Ok(hex::encode(out))
}
