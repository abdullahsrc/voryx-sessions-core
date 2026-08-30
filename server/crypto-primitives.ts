import {
  nativeAes256GcmDecrypt,
  nativeAes256GcmEncrypt,
  nativeConstantTimeEqHex,
  nativeDeriveCommitment,
  nativeDeriveNullifier,
  nativeDeriveOpaqueIndex,
  nativeDeriveProofHash,
  nativeHkdfSha256Hex,
  nativeRandomBytesHex,
  nativeSha256Hex,
  nativeSha256HexFromB64,
} from "./native/crypto-native";

function toHex(buffer: Buffer): string {
  return buffer.toString("hex");
}

function fromHex(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

function toB64(buffer: Buffer): string {
  return buffer.toString("base64");
}

function fromB64(value: string): Buffer {
  return Buffer.from(value, "base64");
}

export function secureRandomBytes(length: number): Buffer {
  const size = Math.max(1, Math.min(4096, Math.floor(Number(length) || 0)));
  const native = nativeRandomBytesHex(size);
  if (native && native.length === size * 2) return fromHex(native);
  throw new Error("Rust native random generator is required but unavailable");
}

export function constantTimeEqualBytes(left: Buffer, right: Buffer): boolean {
  if (left.length !== right.length) return false;
  const native = nativeConstantTimeEqHex(toHex(left), toHex(right));
  if (typeof native === "boolean") return native;
  throw new Error("Rust native constant-time compare is required but unavailable");
}

export function hkdfSha256(
  ikm: Buffer,
  length: number,
  opts?: { salt?: Buffer; info?: Buffer },
): Buffer {
  const outLen = Math.max(1, Math.min(1024, Math.floor(Number(length) || 0)));
  const native = nativeHkdfSha256Hex(
    toHex(ikm),
    outLen,
    opts?.salt && opts.salt.length ? toHex(opts.salt) : undefined,
    opts?.info && opts.info.length ? toHex(opts.info) : undefined,
  );
  if (native) return fromHex(native);
  throw new Error("Rust native HKDF-SHA256 is required but unavailable");
}

export function aes256gcmEncrypt(
  key: Buffer,
  plaintext: Buffer,
  aad?: Buffer,
): { iv: Buffer; tag: Buffer; ciphertext: Buffer } {
  if (key.length !== 32) throw new Error("Invalid AES-256 key length");
  const native = nativeAes256GcmEncrypt(toHex(key), toB64(plaintext), aad?.length ? toB64(aad) : undefined);
  if (native) {
    const iv = fromB64(native.ivB64);
    const tag = fromB64(native.tagB64);
    const ciphertext = fromB64(native.ctB64);
    if (iv.length !== 12 || tag.length !== 16 || ciphertext.length === 0) {
      throw new Error("Invalid native AES-GCM envelope");
    }
    return { iv, tag, ciphertext };
  }
  throw new Error("Rust native AES-256-GCM encryption is required but unavailable");
}

export function aes256gcmDecrypt(
  key: Buffer,
  iv: Buffer,
  tag: Buffer,
  ciphertext: Buffer,
  aad?: Buffer,
): Buffer {
  if (key.length !== 32 || iv.length !== 12 || tag.length !== 16 || !ciphertext.length) {
    throw new Error("Malformed AES-GCM payload");
  }
  const native = nativeAes256GcmDecrypt(
    toHex(key),
    toB64(iv),
    toB64(tag),
    toB64(ciphertext),
    aad?.length ? toB64(aad) : undefined,
  );
  if (native) return fromB64(native);
  throw new Error("Rust native AES-256-GCM decryption is required but unavailable");
}

export function sha256HexUtf8(data: string): string {
  const native = nativeSha256Hex(String(data || ""));
  if (native && /^[a-f0-9]{64}$/i.test(native)) return native.toLowerCase();
  throw new Error("Rust native SHA-256 is required but unavailable");
}

export function sha256HexBytes(data: Buffer | Uint8Array): string {
  const asBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const native = nativeSha256HexFromB64(asBuffer.toString("base64"));
  if (native && /^[a-f0-9]{64}$/i.test(native)) return native.toLowerCase();
  throw new Error("Rust native byte SHA-256 is required but unavailable");
}

export function deriveOpaqueIndex(
  scope: string,
  partA: string,
  partB?: string,
  partC?: string,
  partD?: string,
): string {
  const native = nativeDeriveOpaqueIndex(scope, partA, partB, partC, partD);
  if (native && /^[a-f0-9]{64}$/i.test(native)) return native.toLowerCase();
  throw new Error("Rust native opaque index derivation is required but unavailable");
}

export function deriveCommitment(
  label: string,
  subject: string,
  witness?: string,
  context?: string,
): string {
  const native = nativeDeriveCommitment(label, subject, witness, context);
  if (native && /^[a-f0-9]{64}$/i.test(native)) return native.toLowerCase();
  throw new Error("Rust native commitment derivation is required but unavailable");
}

export function deriveNullifier(seed: string, context?: string): string {
  const native = nativeDeriveNullifier(seed, context);
  if (native && /^[a-f0-9]{64}$/i.test(native)) return native.toLowerCase();
  throw new Error("Rust native nullifier derivation is required but unavailable");
}

export function deriveProofHash(left: string, right: string, context?: string): string {
  const native = nativeDeriveProofHash(left, right, context);
  if (native && /^[a-f0-9]{64}$/i.test(native)) return native.toLowerCase();
  throw new Error("Rust native proof-hash derivation is required but unavailable");
}
