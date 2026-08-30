export function isLikelyPublicKeyHex(value: string): boolean {
  return /^[a-f0-9]{64}$/i.test(String(value || "").trim());
}

export function normalizeSenderPublicKey(value: string): string {
  return String(value || "").trim().toLowerCase();
}

export function isSessionSenderScopeId(value: string): boolean {
  return /^ss2_[a-f0-9]{64}$/i.test(String(value || "").trim());
}
