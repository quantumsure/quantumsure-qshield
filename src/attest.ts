import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha256Hex } from "./hash";
import { qshieldRedact } from "./redact";

export const QSHIELD_POLICY_VERSION = "qshield-redact-v1";
export const QSHIELD_SIG_ALG = "ML-DSA-65";

export type AttestOptions = {
  apiKey: string;
  /** Base64 ML-DSA secret key */
  privateSignatureKeyB64: string;
  policyVersion?: string;
  /** If true (default), run qshieldRedact first. If false, treat text as already safe. */
  redact?: boolean;
};

export type Attestation = {
  textSafe: string;
  contentHash: string;
  signature: string; // base64
  attestedAt: string; // ISO
  policyVersion: string;
  signatureAlgorithm: string;
  apiKey: string;
};

function toB64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let s = "";
  bytes.forEach((b) => {
    s += String.fromCharCode(b);
  });
  return btoa(s);
}

function fromB64(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Same format as server buildMessageToSign */
export function buildMessageToSign(params: {
  apiKey: string;
  policyVersion: string;
  attestedAt: string;
  contentHash: string;
}): string {
  return `v1|${params.apiKey}|${params.policyVersion}|${params.attestedAt}|${params.contentHash}`;
}

/**
 * Redact (optional) + hash + ML-DSA sign.
 * Does not call the network — frontend POSTs the result.
 */
export async function qshieldAttest(
  text: string,
  options: AttestOptions
): Promise<Attestation> {
  const {
    apiKey,
    privateSignatureKeyB64,
    policyVersion = QSHIELD_POLICY_VERSION,
    redact = true,
  } = options;

  if (!apiKey) throw new Error("qshieldAttest: apiKey is required");
  if (!privateSignatureKeyB64) {
    throw new Error("qshieldAttest: privateSignatureKeyB64 is required");
  }

  const textSafe = redact ? qshieldRedact(text) : text;
  const contentHash = await sha256Hex(textSafe);
  const attestedAt = new Date().toISOString();

  const message = buildMessageToSign({
    apiKey,
    policyVersion,
    attestedAt,
    contentHash,
  });

  const secretKey = fromB64(privateSignatureKeyB64);
  const msgBytes = new TextEncoder().encode(message);
  const sigBytes = ml_dsa65.sign(msgBytes, secretKey);

  return {
    textSafe,
    contentHash,
    signature: toB64(sigBytes),
    attestedAt,
    policyVersion,
    signatureAlgorithm: QSHIELD_SIG_ALG,
    apiKey,
  };
}

/**
 * Local verify (optional helper). Server also verifies with publicSignatureKey.
 */
export function qshieldVerify(
  attestation: Pick<
    Attestation,
    "apiKey" | "contentHash" | "signature" | "attestedAt" | "policyVersion"
  >,
  publicSignatureKeyB64: string
): boolean {
  const message = buildMessageToSign({
    apiKey: attestation.apiKey,
    policyVersion: attestation.policyVersion,
    attestedAt: new Date(attestation.attestedAt).toISOString(),
    contentHash: attestation.contentHash,
  });
  const publicKey = fromB64(publicSignatureKeyB64);
  const msgBytes = new TextEncoder().encode(message);
  const signature = fromB64(attestation.signature);
  return ml_dsa65.verify(signature, msgBytes, publicKey);
}
