// verifier-agent 模拟服务接收方：接收请求后调用 SDK 自动验签。
import { createServer } from "node:http";
import { verifyRequest, MemoryNonceStore } from "../src/index.js";
import { verifierDomain, verifierPort } from "./shared.js";

const nonceStore = new MemoryNonceStore();

createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    // 先完整收集 body，确保验签时和发送端使用同一份原始内容。
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const body = Buffer.concat(chunks).toString("utf8");
  const headers = Object.fromEntries(
    Object.entries(req.headers).flatMap(([key, value]) => {
      // Node 原生 req.headers 可能是 string[]，这里统一压平成普通对象。
      if (Array.isArray(value)) {
        return [[key, value.join(",")]];
      }
      return value ? [[key, value]] : [];
    }),
  );

  if ((req.url ?? "/") !== "/invoke" || req.method !== "POST") {
    res.writeHead(404);
    res.end("Not Found");
    return;
  }

  const result = await verifyRequest({
    method: req.method,
    url: `https://${verifierDomain}${req.url}`,
    headers,
    body,
    nonceStore,
    fetch: globalThis.fetch,
  });

  if (!result.ok) {
    // 401 响应直接返回结构化错误码，方便观察失败原因。
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify(result, null, 2));
    return;
  }

  res.writeHead(200, { "content-type": "application/json" });
  // 验签成功后，把解析出的身份信息作为业务上下文返回。
  res.end(
    JSON.stringify(
      {
        ok: true,
        verifiedAgent: result.agentId,
        kid: result.kid,
        organization: result.metadata.organization,
        capabilities: result.metadata.capabilities,
      },
      null,
      2,
    ),
  );
}).listen(verifierPort, () => {
  console.log(`[verifier] running at http://${verifierDomain}`);
  console.log(`[verifier] POST http://${verifierDomain}/invoke`);
});
