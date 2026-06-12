// identity 模块只关心 agent_id 本身的格式和域名绑定关系。
const AGENT_PROTOCOL = "agent:";

export interface ParsedAgentId {
  raw: string;
  domain: string;
  name: string;
}

export function parseAgentId(agentId: string): ParsedAgentId {
  let url: URL;

  try {
    // 直接复用 URL 解析器，减少手写字符串切分的边界错误。
    url = new URL(agentId);
  } catch {
    throw new Error(`Invalid agent_id: ${agentId}`);
  }

  if (url.protocol !== AGENT_PROTOCOL) {
    throw new Error(`Invalid agent_id protocol: ${url.protocol}`);
  }

  if (!url.host) {
    throw new Error("agent_id is missing domain");
  }

  const name = url.pathname.replace(/^\/+/, "");
  if (!name) {
    throw new Error("agent_id is missing agent name");
  }

  // domain 使用 host，天然支持 localhost:3001 这类带端口的本地联调场景。
  return {
    raw: agentId,
    domain: url.host,
    name,
  };
}

export function buildAgentId(domain: string, name: string): string {
  if (!domain) {
    throw new Error("domain is required");
  }

  if (!name) {
    throw new Error("name is required");
  }

  // 构造函数统一清理前导斜杠，避免调用方传入 "/weather" 造成格式不一致。
  return `agent://${domain}/${name.replace(/^\/+/, "")}`;
}

export function assertDomainMatch(agentId: string, metadataDomain: string): void {
  // 核心安全约束：声明身份的 domain 必须和元数据发布域名一致。
  const parsed = parseAgentId(agentId);
  if (parsed.domain !== metadataDomain) {
    throw new Error(
      `Agent domain mismatch: agent_id=${parsed.domain}, metadata=${metadataDomain}`,
    );
  }
}
