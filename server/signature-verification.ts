import { nativeVerifyEd25519 } from "./native/crypto-native";

export function verifySignature(
  data: string,
  signatureHex: string,
  publicKeyHex: string,
): boolean {
  const result = nativeVerifyEd25519(data, signatureHex, publicKeyHex);
  return result === true;
}
