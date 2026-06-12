// send-request 负责模拟一个“真实调用方”，演示如何在发请求前注入签名头。
import { signRequest, LocalKeySigner } from "../src/index.js";
import { primaryKey, publisherAgentId, rotatedKey, verifierDomain } from "./shared.js";

const useRotatedKey = process.env.AGENT_ROTATE === "1";
const signer = new LocalKeySigner({
  kid: useRotatedKey ? "2026-06-11-rotated" : "2026-06-11-main",
  privateKeyPem: useRotatedKey ? rotatedKey.privateKeyPem : primaryKey.privateKeyPem,
});

// 这里故意把签名 URL 写成 https 版本，因为 canonical request 使用的是逻辑访问地址。
const body = JSON.stringify({
  prompt: "weather in shanghai",
});

const signed = await signRequest({
  method: "POST",
  url: `https://${verifierDomain}/invoke`,
  body,
  agentId: publisherAgentId,
  signer,
});

const response = await fetch(`http://${verifierDomain}/invoke`, {
  method: "POST",
  // 实际本地 demo 仍走 http 服务，但验签会使用签名头中的 host/path/body 重建原文。
  headers: {
    "content-type": "application/json",
    ...signed.headers,
  },
  body,
});

console.log(await response.text());
