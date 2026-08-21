import fs from "fs";
import path from "path";
import { createRequire } from "module";

type NativeCryptoBinding = {
  signEd25519?: (data: string, privateKeyHex: string) => string;
  sign_ed25519?: (data: string, privateKeyHex: string) => string;
  verifyEd25519?: (data: string, signatureHex: string, publicKeyHex: string) => boolean;
  verify_ed25519?: (data: string, signatureHex: string, publicKeyHex: string) => boolean;
  generateEd25519KeyPair?: () => {
    publicKeyHex?: string;
    privateKeyHex?: string;
    public_key_hex?: string;
    private_key_hex?: string;
  };
  generate_ed25519_key_pair?: () => {
    publicKeyHex?: string;
    privateKeyHex?: string;
    public_key_hex?: string;
    private_key_hex?: string;
  };
  sealBox1?: (plaintextB64: string, recipientPublicHex: string) => string;
  seal_box1?: (plaintextB64: string, recipientPublicHex: string) => string;
  hkdfSha256Hex?: (ikmHex: string, len: number, saltHex?: string, infoHex?: string) => string;
  hkdf_sha256_hex?: (ikmHex: string, len: number, saltHex?: string, infoHex?: string) => string;
  aes256gcmEncrypt?: (keyHex: string, plaintextB64: string, aadB64?: string) => {
    ivB64?: string;
    tagB64?: string;
    ctB64?: string;
    iv_b64?: string;
    tag_b64?: string;
    ct_b64?: string;
  };
  aes256GcmEncrypt?: (keyHex: string, plaintextB64: string, aadB64?: string) => {
    ivB64?: string;
    tagB64?: string;
    ctB64?: string;
    iv_b64?: string;
    tag_b64?: string;
    ct_b64?: string;
  };
  aes256gcm_encrypt?: (keyHex: string, plaintextB64: string, aadB64?: string) => {
    ivB64?: string;
    tagB64?: string;
    ctB64?: string;
    iv_b64?: string;
    tag_b64?: string;
    ct_b64?: string;
  };
  aes256gcmDecrypt?: (keyHex: string, ivB64: string, tagB64: string, ctB64: string, aadB64?: string) => string;
  aes256GcmDecrypt?: (keyHex: string, ivB64: string, tagB64: string, ctB64: string, aadB64?: string) => string;
  aes256gcm_decrypt?: (keyHex: string, ivB64: string, tagB64: string, ctB64: string, aadB64?: string) => string;
  randomBytesHex?: (len: number) => string;
  random_bytes_hex?: (len: number) => string;
  constantTimeEqHex?: (leftHex: string, rightHex: string) => boolean;
  constant_time_eq_hex?: (leftHex: string, rightHex: string) => boolean;
  sha256Hex?: (data: string) => string;
  sha256_hex?: (data: string) => string;
  sha256HexFromB64?: (dataB64: string) => string;
  sha256_hex_from_b64?: (dataB64: string) => string;
  deriveOpaqueIndex?: (
    scope: string,
    partA: string,
    partB?: string,
    partC?: string,
    partD?: string,
  ) => string;
  derive_opaque_index?: (
    scope: string,
    partA: string,
    partB?: string,
    partC?: string,
    partD?: string,
  ) => string;
  deriveCommitment?: (label: string, subject: string, witness?: string, context?: string) => string;
  derive_commitment?: (label: string, subject: string, witness?: string, context?: string) => string;
  deriveNullifier?: (seed: string, context?: string) => string;
  derive_nullifier?: (seed: string, context?: string) => string;
  deriveProofHash?: (left: string, right: string, context?: string) => string;
  derive_proof_hash?: (left: string, right: string, context?: string) => string;
  canonicalAuthPayloadV1?: (
    ts: number,
    nonce: string,
    method: string,
    path: string,
    bodyHash: string,
    keyId: string,
    publicKey: string,
  ) => string;
  canonical_auth_payload_v1?: (
    ts: number,
    nonce: string,
    method: string,
    path: string,
    bodyHash: string,
    keyId: string,
    publicKey: string,
  ) => string;
  canonicalWsSubscribePayloadV1?: (
    ts: number,
    nonce: string,
    sessionId: string,
    keyId: string,
  ) => string;
  canonical_ws_subscribe_payload_v1?: (
    ts: number,
    nonce: string,
    sessionId: string,
    keyId: string,
  ) => string;
};

type LoadedBinding = {
  binding: NativeCryptoBinding;
  source: string;
};

const require = createRequire(typeof __filename === "string" ? __filename : path.join(process.cwd(), "index.cjs"));

function normalizeBinding(raw: unknown): NativeCryptoBinding | null {
  if (!raw || typeof raw !== "object") return null;
  const candidate = raw as NativeCryptoBinding;
  const signFn = candidate.signEd25519 || candidate.sign_ed25519;
  const verifyFn = candidate.verifyEd25519 || candidate.verify_ed25519;
  if (typeof signFn !== "function" || typeof verifyFn !== "function") return null;
  return candidate;
}

function resolveNativeCandidates(): string[] {
  const explicit = String(process.env.VORYX_CRYPTO_NATIVE_PATH || "").trim();
  const candidates: string[] = [];
  if (explicit) {
    candidates.push(path.isAbsolute(explicit) ? explicit : path.resolve(process.cwd(), explicit));
  }
  const nativeDir = path.resolve(process.cwd(), "native", "voryx-crypto");
  candidates.push(path.join(nativeDir, "index.node"));
  candidates.push(path.join(nativeDir, "voryx_crypto.node"));
  try {
    if (fs.existsSync(nativeDir)) {
      const dynamicNodes = fs
        .readdirSync(nativeDir)
        .filter((name) => name.endsWith(".node"))
        .sort();
      for (const name of dynamicNodes) {
        candidates.push(path.join(nativeDir, name));
      }
    }
  } catch {
  }
  return candidates;
}

function tryLoadNativeBinding(): LoadedBinding | null {
  for (const candidate of resolveNativeCandidates()) {
    try {
      if (!fs.existsSync(candidate)) continue;
      const mod = require(candidate) as unknown;
      const normalized = normalizeBinding(mod) || normalizeBinding((mod as any)?.default);
      if (normalized) return { binding: normalized, source: candidate };
    } catch {
    }
  }
  return null;
}

const loaded = tryLoadNativeBinding();
const nativeBinding = loaded?.binding || null;

export const nativeCryptoEnabled = !!nativeBinding;
export const nativeCryptoSource = loaded?.source || "";

export function nativeSignEd25519(data: string, privateKeyHex: string): string | null {
  if (!nativeBinding) return null;
  try {
    const signFn = nativeBinding.signEd25519 || nativeBinding.sign_ed25519;
    if (typeof signFn !== "function") return null;
    const out = signFn(data, privateKeyHex);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeVerifyEd25519(
  data: string,
  signatureHex: string,
  publicKeyHex: string,
): boolean | null {
  if (!nativeBinding) return null;
  try {
    const verifyFn = nativeBinding.verifyEd25519 || nativeBinding.verify_ed25519;
    if (typeof verifyFn !== "function") return null;
    return !!verifyFn(data, signatureHex, publicKeyHex);
  } catch {
    return null;
  }
}

export function nativeGenerateEd25519KeyPair(): { publicKeyHex: string; privateKeyHex: string } | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.generateEd25519KeyPair || nativeBinding.generate_ed25519_key_pair;
    if (typeof fn !== "function") return null;
    const out = fn();
    if (!out || typeof out !== "object") return null;
    const publicKeyHex = String((out as any).publicKeyHex || (out as any).public_key_hex || "");
    const privateKeyHex = String((out as any).privateKeyHex || (out as any).private_key_hex || "");
    if (!publicKeyHex || !privateKeyHex) return null;
    return { publicKeyHex, privateKeyHex };
  } catch {
    return null;
  }
}

export function nativeSealBox1(plaintextB64: string, recipientPublicHex: string): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.sealBox1 || nativeBinding.seal_box1;
    if (typeof fn !== "function") return null;
    const out = fn(plaintextB64, recipientPublicHex);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeHkdfSha256Hex(
  ikmHex: string,
  len: number,
  saltHex?: string,
  infoHex?: string,
): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.hkdfSha256Hex || nativeBinding.hkdf_sha256_hex;
    if (typeof fn !== "function") return null;
    const out = fn(ikmHex, len, saltHex, infoHex);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeAes256GcmEncrypt(
  keyHex: string,
  plaintextB64: string,
  aadB64?: string,
): { ivB64: string; tagB64: string; ctB64: string } | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.aes256gcmEncrypt || nativeBinding.aes256GcmEncrypt || nativeBinding.aes256gcm_encrypt;
    if (typeof fn !== "function") return null;
    const out = fn(keyHex, plaintextB64, aadB64);
    if (!out || typeof out !== "object") return null;
    const ivB64 = String((out as any).ivB64 || (out as any).iv_b64 || "");
    const tagB64 = String((out as any).tagB64 || (out as any).tag_b64 || "");
    const ctB64 = String((out as any).ctB64 || (out as any).ct_b64 || "");
    if (!ivB64 || !tagB64 || !ctB64) return null;
    return { ivB64, tagB64, ctB64 };
  } catch {
    return null;
  }
}

export function nativeAes256GcmDecrypt(
  keyHex: string,
  ivB64: string,
  tagB64: string,
  ctB64: string,
  aadB64?: string,
): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.aes256gcmDecrypt || nativeBinding.aes256GcmDecrypt || nativeBinding.aes256gcm_decrypt;
    if (typeof fn !== "function") return null;
    const out = fn(keyHex, ivB64, tagB64, ctB64, aadB64);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeRandomBytesHex(len: number): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.randomBytesHex || nativeBinding.random_bytes_hex;
    if (typeof fn !== "function") return null;
    const out = fn(len);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeConstantTimeEqHex(leftHex: string, rightHex: string): boolean | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.constantTimeEqHex || nativeBinding.constant_time_eq_hex;
    if (typeof fn !== "function") return null;
    return !!fn(leftHex, rightHex);
  } catch {
    return null;
  }
}

export function nativeSha256Hex(data: string): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.sha256Hex || nativeBinding.sha256_hex;
    if (typeof fn !== "function") return null;
    const out = fn(data);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeSha256HexFromB64(dataB64: string): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.sha256HexFromB64 || nativeBinding.sha256_hex_from_b64;
    if (typeof fn !== "function") return null;
    const out = fn(dataB64);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeDeriveOpaqueIndex(
  scope: string,
  partA: string,
  partB?: string,
  partC?: string,
  partD?: string,
): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.deriveOpaqueIndex || nativeBinding.derive_opaque_index;
    if (typeof fn !== "function") return null;
    const out = fn(scope, partA, partB, partC, partD);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeDeriveCommitment(
  label: string,
  subject: string,
  witness?: string,
  context?: string,
): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.deriveCommitment || nativeBinding.derive_commitment;
    if (typeof fn !== "function") return null;
    const out = fn(label, subject, witness, context);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeDeriveNullifier(seed: string, context?: string): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.deriveNullifier || nativeBinding.derive_nullifier;
    if (typeof fn !== "function") return null;
    const out = fn(seed, context);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeDeriveProofHash(left: string, right: string, context?: string): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.deriveProofHash || nativeBinding.derive_proof_hash;
    if (typeof fn !== "function") return null;
    const out = fn(left, right, context);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeCanonicalAuthPayloadV1(input: {
  ts: number;
  nonce: string;
  method: string;
  path: string;
  bodyHash: string;
  keyId: string;
  publicKey: string;
}): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.canonicalAuthPayloadV1 || nativeBinding.canonical_auth_payload_v1;
    if (typeof fn !== "function") return null;
    const out = fn(
      input.ts,
      input.nonce,
      input.method,
      input.path,
      input.bodyHash,
      input.keyId,
      input.publicKey,
    );
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}

export function nativeCanonicalWsSubscribePayloadV1(input: {
  ts: number;
  nonce: string;
  sessionId: string;
  keyId: string;
}): string | null {
  if (!nativeBinding) return null;
  try {
    const fn = nativeBinding.canonicalWsSubscribePayloadV1 || nativeBinding.canonical_ws_subscribe_payload_v1;
    if (typeof fn !== "function") return null;
    const out = fn(input.ts, input.nonce, input.sessionId, input.keyId);
    return typeof out === "string" ? out : null;
  } catch {
    return null;
  }
}
