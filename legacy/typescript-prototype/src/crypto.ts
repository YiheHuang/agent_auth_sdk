// crypto 模块负责所有和密钥、摘要、签名验签直接相关的能力。
import { createHash, generateKeyPairSync, sign as nodeSign, verify as nodeVerify, createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { fromBase64Url, toBase64Url } from "./encoding.js";
import type { Signer } from "./types.js";

export interface GeneratedKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  publicKeyBase64Url: string;
}

export interface KMSSigner extends Signer {
  kind: "kms";
}

export class LocalKeySigner implements Signer {
  readonly #kidValue: string;
  readonly #privateKey: KeyObject;

  constructor(input: { kid: string; privateKeyPem: string }) {
    this.#kidValue = input.kid;
    // 本地 demo 直接从 PEM 加载私钥；后续 KMS 实现只需复用同一接口。
    this.#privateKey = createPrivateKey(input.privateKeyPem);
  }

  async kid(): Promise<string> {
    return this.#kidValue;
  }

  async algorithm(): Promise<"Ed25519"> {
    return "Ed25519";
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(nodeSign(null, data, this.#privateKey));
  }
}

export function generateKeyPair(): GeneratedKeyPair {
  // v1 统一选 Ed25519：签名短、实现简单、Node 原生支持好。
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");

  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });

  return {
    privateKeyPem,
    publicKeyPem,
    publicKeyBase64Url: toBase64Url(new Uint8Array(publicKeyDer)),
  };
}

export function sha256Base64Url(data: Uint8Array): string {
  // body 摘要进入 canonical request，避免签名对象过大且保持协议稳定。
  return createHash("sha256").update(data).digest("base64url");
}

export function verifySignature(input: {
  data: Uint8Array;
  signatureBase64Url: string;
  publicKeyBase64Url: string;
}): boolean {
  // metadata 中保存的是 DER 编码后的公钥，验签时先还原成 KeyObject。
  const publicKeyDer = fromBase64Url(input.publicKeyBase64Url);
  const publicKey = createPublicKey({
    key: Buffer.from(publicKeyDer),
    format: "der",
    type: "spki",
  });

  return nodeVerify(
    null,
    input.data,
    publicKey,
    Buffer.from(input.signatureBase64Url, "base64url"),
  );
}
