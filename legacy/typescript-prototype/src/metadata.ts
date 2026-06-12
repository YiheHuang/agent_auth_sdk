// metadata 模块负责通过 well-known 文档发现 Agent 身份并做基础校验。
import { assertDomainMatch, parseAgentId } from "./identity.js";
import type { AgentKey, AgentMetadata, ResolveResult, ResolverOptions } from "./types.js";

interface CacheEntry {
  result: ResolveResult;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();
const DEFAULT_CACHE_TTL_SECONDS = 300;

function isLocalhostDomain(domain: string): boolean {
  return domain.startsWith("localhost:") || domain.startsWith("127.0.0.1:");
}

function isIsoDate(input: string | undefined): boolean {
  if (!input) {
    return false;
  }

  return !Number.isNaN(Date.parse(input));
}

function validateMetadata(metadata: AgentMetadata): void {
  // 这里做的是运行时校验，目标是即使没有额外 schema 库也能尽早发现脏数据。
  if (!metadata || typeof metadata !== "object") {
    throw new Error("metadata must be an object");
  }

  if (!metadata.agent_id || !metadata.domain || !metadata.endpoint) {
    throw new Error("metadata is missing required fields");
  }

  assertDomainMatch(metadata.agent_id, metadata.domain);

  const endpoint = new URL(metadata.endpoint);
  const isLocalhost = endpoint.hostname === "localhost" || endpoint.hostname === "127.0.0.1";
  // 正式环境强制 HTTPS，本地 demo 为了方便联调允许 localhost 走 HTTP。
  if (endpoint.protocol !== "https:" && !(isLocalhost && endpoint.protocol === "http:")) {
    throw new Error("endpoint must use https, localhost demo may use http");
  }

  if (!Array.isArray(metadata.capabilities) || !Array.isArray(metadata.keys)) {
    throw new Error("metadata capabilities and keys must be arrays");
  }

  if (!Array.isArray(metadata.revoked_kids)) {
    throw new Error("metadata revoked_kids must be an array");
  }

  if (!isIsoDate(metadata.updated_at)) {
    throw new Error("metadata updated_at must be an ISO date");
  }

  const seenKids = new Set<string>();
  for (const key of metadata.keys) {
    // kid 唯一性是轮换逻辑成立的前提。
    if (!key.kid || !key.public_key || key.alg !== "Ed25519") {
      throw new Error("metadata key is invalid");
    }

    if (seenKids.has(key.kid)) {
      throw new Error(`duplicate kid: ${key.kid}`);
    }
    seenKids.add(key.kid);

    if (key.not_before && !isIsoDate(key.not_before)) {
      throw new Error(`invalid not_before: ${key.kid}`);
    }

    if (key.not_after && !isIsoDate(key.not_after)) {
      throw new Error(`invalid not_after: ${key.kid}`);
    }
  }
}

export async function resolveAgent(
  agentId: string,
  options: ResolverOptions = {},
): Promise<ResolveResult> {
  const parsed = parseAgentId(agentId);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) {
    throw new Error("fetch implementation is required");
  }

  const ttlMs = (options.cacheTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS) * 1000;
  const cacheKey = parsed.raw;
  const cached = cache.get(cacheKey);
  const now = Date.now();

  if (cached && cached.expiresAt > now) {
    // 命中有效缓存时直接返回，避免每次验签都访问远程域名。
    return cached.result;
  }

  // localhost 联调用 http，其他场景默认 https。
  const scheme = isLocalhostDomain(parsed.domain) ? "http" : "https";
  const wellKnownUrl = `${scheme}://${parsed.domain}/.well-known/agent.json`;
  const headers: HeadersInit = {};
  if (cached?.result.etag) {
    // 如果上次有 ETag，这里尝试条件请求以减少重复拉取。
    headers["If-None-Match"] = cached.result.etag;
  }

  try {
    const response = await fetchImpl(wellKnownUrl, { headers });
    if (response.status === 304 && cached) {
      // 远端未变化时只刷新本地 TTL，不重复解析 JSON。
      const updated = {
        ...cached,
        expiresAt: now + ttlMs,
      };
      cache.set(cacheKey, updated);
      return updated.result;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const metadata = (await response.json()) as AgentMetadata;
    validateMetadata(metadata);
    assertDomainMatch(agentId, metadata.domain);

    const etag = response.headers.get("etag");
    const result: ResolveResult = etag
      ? {
          metadata,
          resolvedAt: new Date().toISOString(),
          etag,
        }
      : {
          metadata,
          resolvedAt: new Date().toISOString(),
        };

    cache.set(cacheKey, { result, expiresAt: now + ttlMs });
    return result;
  } catch (error) {
    if (cached && cached.expiresAt > now) {
      // 远端临时失败时允许回退到仍然有效的旧缓存，提升可用性。
      return cached.result;
    }

    throw error;
  }
}

export function getActiveKey(metadata: AgentMetadata, kid?: string, now = new Date()): AgentKey {
  // 如果请求明确带了 kid，就优先精确匹配，不做模糊兜底。
  if (kid && metadata.revoked_kids.includes(kid)) {
    throw new Error(`Key revoked: ${kid}`);
  }

  const matches = metadata.keys.filter((key) => {
    if (kid && key.kid !== kid) {
      return false;
    }

    if (metadata.revoked_kids.includes(key.kid)) {
      return false;
    }

    if (key.status !== "active") {
      return false;
    }

    // active + 时间窗 + 未吊销，共同决定这把 key 是否可用于当前验签。
    const current = now.getTime();
    const notBefore = key.not_before ? Date.parse(key.not_before) : undefined;
    const notAfter = key.not_after ? Date.parse(key.not_after) : undefined;

    if (notBefore !== undefined && notBefore > current) {
      return false;
    }

    if (notAfter !== undefined && notAfter < current) {
      return false;
    }

    return true;
  });

  if (matches.length === 0) {
    throw new Error(kid ? `Active key not found for kid=${kid}` : "No active key found");
  }

  return matches[0]!;
}

export function clearMetadataCache(): void {
  // 测试里会主动清缓存，避免不同 case 之间互相污染。
  cache.clear();
}
