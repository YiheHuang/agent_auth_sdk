// demo 的共享常量统一放在这里，避免三个脚本之间复制粘贴配置。
import { buildAgentId } from "../src/index.js";

export const publisherPort = 3001;
export const verifierPort = 3002;
export const publisherDomain = `localhost:${publisherPort}`;
export const verifierDomain = `localhost:${verifierPort}`;
export const publisherAgentId = buildAgentId(publisherDomain, "weather");

// 这里使用固定 demo 密钥，确保不同进程启动时公私钥保持一致，联调结果可复现。
export const primaryKey = {
  privateKeyPem: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGLpgHDYIIW/p9qoJq5qMrG9zlhc+CBHUWOw1AC8cAMc
-----END PRIVATE KEY-----
`,
  publicKeyBase64Url: "MCowBQYDK2VwAyEAjtjKZOT52Emf39SWzQfOOdbyLjxAfGkMDXXrHtw29V4",
};

export const rotatedKey = {
  privateKeyPem: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIE8A9X1uaJu0cE6LZpDTO5RMz4IUUj++pjIJx+xfdK84
-----END PRIVATE KEY-----
`,
  publicKeyBase64Url: "MCowBQYDK2VwAyEAIxs804FspYTuI2dl3Fo6ejsM-SDUS3r_UAsHkOO-57U",
};
