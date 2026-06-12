// adapters 模块提供对常见集成场景的轻量封装，避免业务层重复拼 header。
import { signRequest, verifyRequest } from "./auth.js";
import type { NonceStore, Signer, VerifyRequestResult } from "./types.js";

export async function createSignedFetch(input: {
  agentId: string;
  signer: Signer;
  fetch?: typeof globalThis.fetch;
}) {
  const fetchImpl = input.fetch ?? globalThis.fetch;
  if (!fetchImpl) {
    throw new Error("fetch implementation is required");
  }

  return async (url: string, init: RequestInit = {}) => {
    // 这个适配器适合普通 REST/A2A 调用：先签名，再把头透传给 fetch。
    const method = init.method ?? "GET";
    const body = typeof init.body === "string" ? init.body : undefined;
    const headers = Object.fromEntries(new Headers(init.headers ?? {}).entries());
    const signInput = {
      method,
      url,
      headers,
      agentId: input.agentId,
      signer: input.signer,
      ...(body !== undefined ? { body } : {}),
    };
    const signed = await signRequest(signInput);

    return fetchImpl(url, {
      ...init,
      headers: signed.headers,
    });
  };
}

export async function verifyNodeRequest(input: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  nonceStore: NonceStore;
  fetch?: typeof globalThis.fetch;
}): Promise<VerifyRequestResult> {
  // 这里是给 Node HTTP 服务的简化包装，避免每次手动组装 verifyRequest 入参。
  const verifyInput = {
    method: input.method,
    url: input.url,
    headers: input.headers,
    nonceStore: input.nonceStore,
    ...(input.body !== undefined ? { body: input.body } : {}),
    ...(input.fetch ? { fetch: input.fetch } : {}),
  };
  return verifyRequest(verifyInput);
}

export function attachMcpAuthHeaders(headers: Record<string, string>, signedHeaders: Record<string, string>): Record<string, string> {
  // MCP 适配目前先走最朴素的 header 合并，后续可扩展 metadata 注入方案。
  return {
    ...headers,
    ...signedHeaders,
  };
}
