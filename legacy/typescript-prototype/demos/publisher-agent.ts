// publisher-agent 模拟身份发布方：公开 well-known 文档和一个普通业务接口。
import { createServer } from "node:http";
import { URL } from "node:url";
import { publisherAgentId, publisherDomain, publisherPort, primaryKey, rotatedKey } from "./shared.js";

const useRotatedKey = process.env.AGENT_ROTATE === "1";

// 通过环境变量切换主 key / 轮换后 key，便于手工验证轮换与吊销逻辑。
const metadata = {
  version: "1.0",
  agent_id: publisherAgentId,
  domain: publisherDomain,
  name: "weather",
  organization: "Demo Org",
  endpoint: `http://${publisherDomain}/api/agent`,
  capabilities: ["mcp", "a2a", "openai-agents"],
  keys: [
    {
      kid: useRotatedKey ? "2026-06-11-rotated" : "2026-06-11-main",
      alg: "Ed25519",
      public_key: useRotatedKey ? rotatedKey.publicKeyBase64Url : primaryKey.publicKeyBase64Url,
      status: "active",
      not_before: "2026-06-11T00:00:00Z",
      not_after: "2027-06-11T00:00:00Z",
    },
  ],
  revoked_kids: useRotatedKey ? ["2026-06-11-main"] : [],
  updated_at: new Date().toISOString(),
};

createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://${publisherDomain}`);
  if (url.pathname === "/.well-known/agent.json") {
    // 这是身份发现的核心入口，验证方会从这里拉取公钥和组织信息。
    res.writeHead(200, {
      "content-type": "application/json",
      etag: useRotatedKey ? "rotated" : "main",
    });
    res.end(JSON.stringify(metadata, null, 2));
    return;
  }

  if (url.pathname === "/api/agent") {
    // 这个接口不是验签必须项，只是示意“已发布的 Agent 业务 endpoint”。
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, from: publisherAgentId }));
    return;
  }

  res.writeHead(404);
  res.end("Not Found");
}).listen(publisherPort, () => {
  console.log(`[publisher] running at http://${publisherDomain}`);
  console.log(`[publisher] metadata at http://${publisherDomain}/.well-known/agent.json`);
  console.log(`[publisher] active kid=${useRotatedKey ? "2026-06-11-rotated" : "2026-06-11-main"}`);
});
