// 这里集中定义 SDK 对外暴露的核心类型，避免模块之间出现隐式约定。
export type AgentKeyAlgorithm = "Ed25519";

export interface AgentKey {
  // kid 用于在请求里精确指向某一把公钥，支撑轮换与吊销。
  kid: string;
  alg: AgentKeyAlgorithm;
  public_key: string;
  status: "active" | "inactive";
  not_before?: string;
  not_after?: string;
}

export interface AgentMetadata {
  // version 预留协议演进空间，v1 从 1.0 开始。
  version: "1.0" | string;
  agent_id: string;
  domain: string;
  name: string;
  organization: string;
  endpoint: string;
  capabilities: string[];
  keys: AgentKey[];
  revoked_kids: string[];
  updated_at: string;
}

export interface ResolveResult {
  // resolvedAt 表示本次解析成功的本地时间，便于调试缓存行为。
  metadata: AgentMetadata;
  resolvedAt: string;
  etag?: string;
}

export interface ResolverOptions {
  // cacheTtlSeconds 控制 metadata 的内存缓存时长。
  cacheTtlSeconds?: number;
  fetch?: typeof globalThis.fetch;
}

export interface Signer {
  // SDK 通过统一的 Signer 接口兼容本地私钥与未来的 KMS 实现。
  kid(): Promise<string>;
  algorithm(): Promise<"Ed25519">;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface NonceStore {
  // NonceStore 是重放保护的关键抽象，生产环境可替换为 Redis 等共享存储。
  has(key: string): Promise<boolean>;
  set(key: string, ttlSeconds: number): Promise<void>;
}

export interface SignRequestInput {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  agentId: string;
  signer: Signer;
  timestamp?: string;
  nonce?: string;
}

export interface SignRequestResult {
  headers: Record<string, string>;
  canonical: string;
}

export type VerifyErrorCode =
  // 这些错误码固定下来，方便上层做稳定分支判断。
  | "INVALID_AGENT_ID"
  | "METADATA_FETCH_FAILED"
  | "METADATA_DOMAIN_MISMATCH"
  | "KEY_NOT_FOUND"
  | "KEY_REVOKED"
  | "SIGNATURE_INVALID"
  | "TIMESTAMP_EXPIRED"
  | "NONCE_REPLAYED";

export type VerifyRequestResult =
  | {
      ok: true;
      agentId: string;
      kid: string;
      metadata: AgentMetadata;
      canonical: string;
    }
  | {
      ok: false;
      code: VerifyErrorCode;
      reason: string;
    };

export interface VerifyRequestInput {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Uint8Array;
  nonceStore: NonceStore;
  fetch?: typeof globalThis.fetch;
  now?: Date;
  clockSkewSeconds?: number;
  nonceTtlSeconds?: number;
}

export interface MetadataResolver {
  // 预留解析器抽象，便于未来替换缓存策略或底层 transport。
  resolveAgent(agentId: string, options?: ResolverOptions): Promise<ResolveResult>;
}
