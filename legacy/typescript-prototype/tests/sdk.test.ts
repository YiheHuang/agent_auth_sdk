// 这组测试覆盖当前 SDK 的最关键行为：身份解析、签名验签、重放保护和轮换。
import { beforeEach, describe, expect, it } from "vitest";
import { buildCanonicalRequest, signRequest, verifyRequest } from "../src/auth.js";
import { generateKeyPair, LocalKeySigner } from "../src/crypto.js";
import { buildAgentId, parseAgentId } from "../src/identity.js";
import { clearMetadataCache } from "../src/metadata.js";
import { MemoryNonceStore } from "../src/nonce.js";
import type { AgentMetadata } from "../src/types.js";

function createMetadata(input: {
  agentId: string;
  domain: string;
  endpoint: string;
  publicKey: string;
  kid?: string;
  revokedKids?: string[];
}): AgentMetadata {
  // 测试里通过工厂函数快速构造 metadata，避免每个 case 重复大段样板数据。
  return {
    version: "1.0",
    agent_id: input.agentId,
    domain: input.domain,
    name: "weather",
    organization: "Demo Org",
    endpoint: input.endpoint,
    capabilities: ["mcp", "a2a"],
    keys: [
      {
        kid: input.kid ?? "test-main",
        alg: "Ed25519",
        public_key: input.publicKey,
        status: "active",
        not_before: "2026-01-01T00:00:00Z",
        not_after: "2027-01-01T00:00:00Z",
      },
    ],
    revoked_kids: input.revokedKids ?? [],
    updated_at: "2026-06-11T00:00:00Z",
  };
}

describe("agent identity sdk", () => {
  beforeEach(() => {
    // 每个 case 前清缓存，保证 metadata 解析行为可预测。
    clearMetadataCache();
  });

  it("parses and builds agent_id", () => {
    const agentId = buildAgentId("demo.example.com", "weather");
    expect(agentId).toBe("agent://demo.example.com/weather");
    expect(parseAgentId(agentId)).toEqual({
      raw: "agent://demo.example.com/weather",
      domain: "demo.example.com",
      name: "weather",
    });
  });

  it("builds stable canonical request", () => {
    const canonical = buildCanonicalRequest({
      method: "post",
      url: "https://demo.example.com/api/agent?foo=bar",
      body: '{"city":"shanghai"}',
      agentId: "agent://demo.example.com/weather",
      kid: "kid-1",
      timestamp: "2026-06-11T00:00:00Z",
      nonce: "nonce-1",
    });

    // 这里只验证签名串中的关键字段，确保协议输出稳定。
    expect(canonical).toContain("POST");
    expect(canonical).toContain("/api/agent?foo=bar");
    expect(canonical).toContain("x-agent-id:agent://demo.example.com/weather");
  });

  it("signs and verifies a request", async () => {
    const keyPair = generateKeyPair();
    const signer = new LocalKeySigner({
      kid: "test-main",
      privateKeyPem: keyPair.privateKeyPem,
    });

    const agentId = "agent://localhost:3001/weather";
    const metadata = createMetadata({
      agentId,
      domain: "localhost:3001",
      endpoint: "http://localhost:3001/api/agent",
      publicKey: keyPair.publicKeyBase64Url,
    });

    // 用 fetch mock 模拟远端 well-known 文档，测试完整发现 + 验签链路。
    const fetchMock: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify(metadata), {
        status: 200,
        headers: { "content-type": "application/json", etag: "v1" },
      });

    const signed = await signRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      body: '{"task":"weather"}',
      agentId,
      signer,
      timestamp: "2026-06-11T00:00:00Z",
      nonce: "nonce-1",
    });

    const result = await verifyRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      headers: signed.headers,
      body: '{"task":"weather"}',
      nonceStore: new MemoryNonceStore(),
      fetch: fetchMock,
      now: new Date("2026-06-11T00:03:00Z"),
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.agentId).toBe(agentId);
      expect(result.kid).toBe("test-main");
    }
  });

  it("rejects replayed nonces", async () => {
    const keyPair = generateKeyPair();
    const signer = new LocalKeySigner({
      kid: "test-main",
      privateKeyPem: keyPair.privateKeyPem,
    });

    const agentId = "agent://localhost:3001/weather";
    const metadata = createMetadata({
      agentId,
      domain: "localhost:3001",
      endpoint: "http://localhost:3001/api/agent",
      publicKey: keyPair.publicKeyBase64Url,
    });

    const fetchMock: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify(metadata), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const signed = await signRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      body: '{"task":"weather"}',
      agentId,
      signer,
      timestamp: "2026-06-11T00:00:00Z",
      nonce: "nonce-1",
    });

    const nonceStore = new MemoryNonceStore();
    // 同一 nonce 连续验证两次，第二次必须被视为重放。
    const first = await verifyRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      headers: signed.headers,
      body: '{"task":"weather"}',
      nonceStore,
      fetch: fetchMock,
      now: new Date("2026-06-11T00:03:00Z"),
    });

    const second = await verifyRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      headers: signed.headers,
      body: '{"task":"weather"}',
      nonceStore,
      fetch: fetchMock,
      now: new Date("2026-06-11T00:03:10Z"),
    });

    expect(first.ok).toBe(true);
    expect(second).toEqual({
      ok: false,
      code: "NONCE_REPLAYED",
      reason: "Nonce has already been used",
    });
  });

  it("rejects revoked kid", async () => {
    const keyPair = generateKeyPair();
    const signer = new LocalKeySigner({
      kid: "test-main",
      privateKeyPem: keyPair.privateKeyPem,
    });

    const agentId = "agent://localhost:3001/weather";
    const metadata = createMetadata({
      agentId,
      domain: "localhost:3001",
      endpoint: "http://localhost:3001/api/agent",
      publicKey: keyPair.publicKeyBase64Url,
      revokedKids: ["test-main"],
    });

    const fetchMock: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify(metadata), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const signed = await signRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      body: '{"task":"weather"}',
      agentId,
      signer,
      timestamp: "2026-06-11T00:00:00Z",
      nonce: "nonce-1",
    });

    // metadata 显式吊销 kid 后，即使签名正确也必须拒绝。
    const result = await verifyRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      headers: signed.headers,
      body: '{"task":"weather"}',
      nonceStore: new MemoryNonceStore(),
      fetch: fetchMock,
      now: new Date("2026-06-11T00:03:00Z"),
    });

    expect(result).toEqual({
      ok: false,
      code: "KEY_REVOKED",
      reason: "Key revoked: test-main",
    });
  });

  it("rejects mismatched metadata domain", async () => {
    const keyPair = generateKeyPair();
    const signer = new LocalKeySigner({
      kid: "test-main",
      privateKeyPem: keyPair.privateKeyPem,
    });

    const agentId = "agent://localhost:3001/weather";
    const metadata = createMetadata({
      agentId,
      domain: "localhost:3009",
      endpoint: "http://localhost:3001/api/agent",
      publicKey: keyPair.publicKeyBase64Url,
    });

    const fetchMock: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify(metadata), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const signed = await signRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      body: '{"task":"weather"}',
      agentId,
      signer,
      timestamp: "2026-06-11T00:00:00Z",
      nonce: "nonce-1",
    });

    // well-known 发布域名和 agent_id 不一致时，说明身份绑定不可信。
    const result = await verifyRequest({
      method: "POST",
      url: "https://localhost:3002/invoke",
      headers: signed.headers,
      body: '{"task":"weather"}',
      nonceStore: new MemoryNonceStore(),
      fetch: fetchMock,
      now: new Date("2026-06-11T00:03:00Z"),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("METADATA_DOMAIN_MISMATCH");
    }
  });
});
