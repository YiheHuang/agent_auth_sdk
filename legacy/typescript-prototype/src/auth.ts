// auth 模块实现请求签名与验签，是 SDK 的核心安全链路。
import { randomUUID } from "node:crypto";
import { toUint8Array, toBase64Url } from "./encoding.js";
import { parseAgentId } from "./identity.js";
import { resolveAgent, getActiveKey } from "./metadata.js";
import { sha256Base64Url, verifySignature } from "./crypto.js";
import type { SignRequestInput, SignRequestResult, VerifyRequestInput, VerifyRequestResult } from "./types.js";

const DEFAULT_CLOCK_SKEW_SECONDS = 300;
const DEFAULT_NONCE_TTL_SECONDS = 600;

function headerLookup(headers: Record<string, string>, name: string): string | undefined {
  // HTTP header 大小写不敏感，因此统一走小写匹配。
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      return value;
    }
  }
  return undefined;
}

function canonicalizeHeaders(headers: Record<string, string>): Record<string, string> {
  // 对外保留普通对象形式，内部统一转小写，减少调用方 header 风格差异。
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
}

export function buildCanonicalRequest(input: {
  method: string;
  url: string;
  body?: string | Uint8Array;
  agentId: string;
  kid: string;
  timestamp: string;
  nonce: string;
  host?: string;
}): string {
  const url = new URL(input.url);
  // body 不直接入签名串，而是先做摘要，保证协议简单且可复现。
  const bodyDigest = sha256Base64Url(toUint8Array(input.body));
  const host = input.host ?? url.host;

  // canonical string 的字段顺序固定，一旦改变就会导致签名不兼容。
  return [
    input.method.toUpperCase(),
    `${url.pathname}${url.search}`,
    bodyDigest,
    `x-agent-id:${input.agentId}`,
    `x-agent-kid:${input.kid}`,
    `x-agent-timestamp:${input.timestamp}`,
    `x-agent-nonce:${input.nonce}`,
    `host:${host}`,
  ].join("\n");
}

export async function signRequest(input: SignRequestInput): Promise<SignRequestResult> {
  parseAgentId(input.agentId);

  const kid = await input.signer.kid();
  const algorithm = await input.signer.algorithm();
  if (algorithm !== "Ed25519") {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const timestamp = input.timestamp ?? new Date().toISOString();
  // nonce 默认自动生成，调用方也可以显式传入以便测试复现。
  const nonce = input.nonce ?? randomUUID();
  const url = new URL(input.url);
  const headers = canonicalizeHeaders(input.headers ?? {});

  headers.host = headers.host ?? url.host;

  // 签名前先构造统一的 canonical request，保证发送端与接收端完全一致。
  const canonicalInput = {
    method: input.method,
    url: input.url,
    agentId: input.agentId,
    kid,
    timestamp,
    nonce,
    host: headers.host,
    ...(input.body !== undefined ? { body: input.body } : {}),
  };
  const canonical = buildCanonicalRequest(canonicalInput);

  const signature = await input.signer.sign(new TextEncoder().encode(canonical));
  // 将签名相关头回填到 headers，调用方可直接用于 HTTP 请求。
  headers["x-agent-id"] = input.agentId;
  headers["x-agent-kid"] = kid;
  headers["x-agent-timestamp"] = timestamp;
  headers["x-agent-nonce"] = nonce;
  headers["x-agent-signature-input"] =
    "method path body-digest x-agent-id x-agent-kid x-agent-timestamp x-agent-nonce host";
  headers["x-agent-signature"] = toBase64Url(signature);

  return { headers, canonical };
}

export async function verifyRequest(input: VerifyRequestInput): Promise<VerifyRequestResult> {
  try {
    const headers = canonicalizeHeaders(input.headers);
    const agentId = headerLookup(headers, "x-agent-id");
    const kid = headerLookup(headers, "x-agent-kid");
    const timestamp = headerLookup(headers, "x-agent-timestamp");
    const nonce = headerLookup(headers, "x-agent-nonce");
    const signature = headerLookup(headers, "x-agent-signature");
    const host = headerLookup(headers, "host") ?? new URL(input.url).host;

    if (!agentId || !kid || !timestamp || !nonce || !signature) {
      return { ok: false, code: "SIGNATURE_INVALID", reason: "Missing required signature headers" };
    }

    parseAgentId(agentId);

    const now = input.now ?? new Date();
    const skewSeconds = input.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    // 时间窗用于抵御离线重放，默认允许 5 分钟时钟偏差。
    const diffSeconds = Math.abs(now.getTime() - Date.parse(timestamp)) / 1000;
    if (Number.isNaN(diffSeconds) || diffSeconds > skewSeconds) {
      return { ok: false, code: "TIMESTAMP_EXPIRED", reason: "Request timestamp is outside allowed skew" };
    }

    const nonceKey = `${agentId}:${nonce}`;
    if (await input.nonceStore.has(nonceKey)) {
      return { ok: false, code: "NONCE_REPLAYED", reason: "Nonce has already been used" };
    }

    let resolved;
    try {
      // 验签前必须先完成身份发现，拿到声明中的公钥集合。
      resolved = await resolveAgent(agentId, input.fetch ? { fetch: input.fetch } : {});
    } catch (error) {
      const reason = error instanceof Error ? error.message : "Unknown metadata fetch error";
      if (reason.includes("mismatch")) {
        return { ok: false, code: "METADATA_DOMAIN_MISMATCH", reason };
      }
      return { ok: false, code: "METADATA_FETCH_FAILED", reason };
    }

    const metadata = resolved.metadata;
    if (metadata.revoked_kids.includes(kid)) {
      return { ok: false, code: "KEY_REVOKED", reason: `Key revoked: ${kid}` };
    }

    let key;
    try {
      key = getActiveKey(metadata, kid, now);
    } catch (error) {
      return {
        ok: false,
        code: "KEY_NOT_FOUND",
        reason: error instanceof Error ? error.message : "Active key not found",
      };
    }

    // 接收端按完全相同的规则重建签名原文，再用公钥验签。
    const canonicalInput = {
      method: input.method,
      url: input.url,
      agentId,
      kid,
      timestamp,
      nonce,
      host,
      ...(input.body !== undefined ? { body: input.body } : {}),
    };
    const canonical = buildCanonicalRequest(canonicalInput);

    const verified = verifySignature({
      data: new TextEncoder().encode(canonical),
      signatureBase64Url: signature,
      publicKeyBase64Url: key.public_key,
    });

    if (!verified) {
      return { ok: false, code: "SIGNATURE_INVALID", reason: "Signature verification failed" };
    }

    // 只有验签成功后才写入 nonce，避免无效请求污染缓存。
    await input.nonceStore.set(nonceKey, input.nonceTtlSeconds ?? DEFAULT_NONCE_TTL_SECONDS);

    return {
      ok: true,
      agentId,
      kid,
      metadata,
      canonical,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : "Unknown verification error";
    if (reason.startsWith("Invalid agent_id")) {
      return { ok: false, code: "INVALID_AGENT_ID", reason };
    }
    return { ok: false, code: "SIGNATURE_INVALID", reason };
  }
}
