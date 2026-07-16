# SignedEnvelope v1

本文是 Agent Auth 1.x 的规范性 wire protocol。所有本地 Agent 调用、远程请求/响应和 Registry 写操作都使用同一种 envelope。

```json
{
  "v": 1,
  "id": "018f...",
  "sender": "agent://agents.example.com/coordinator",
  "audience": "agent://agents.example.com/researcher",
  "kid": "agent://agents.example.com/coordinator#key:v2",
  "issued_at": "2026-07-15T12:00:00Z",
  "type": "agent.call",
  "reply_to": null,
  "payload": "eyJxdWVyeSI6ImhlbGxvIn0",
  "signature": "MEUCIQ..."
}
```

## 编码与签名

- envelope 必须恰好包含上述十个字段；`v` 必须为整数 `1`。
- `issued_at` 必须是 UTC、RFC 3339、秒级 `YYYY-MM-DDTHH:MM:SSZ`。
- `payload` 是严格 JSON UTF-8 bytes 的无 padding base64url；拒绝 NaN、Infinity、重复 object key、非字符串 object key 和不可序列化值。
- 签名输入是移除 `signature` 后的对象，以 UTF-8 JSON 编码：key 排序、无多余空白、`,`/`:` 分隔、Unicode 不转义。
- 签名算法固定为 P-256 + SHA-256；签名编码为 ASN.1 DER，再做无 padding base64url。
- 公钥固定为 P-256 SubjectPublicKeyInfo DER，再做无 padding base64url。

接收端依次验证 sender/kid、audience、type、reply correlation、时间窗口、签名和 nonce。`id` 是 request ID，也是 `(sender, id)` 防重放键；只有验签成功后才能原子消费。

## 调用类型

| type | sender → audience | reply_to |
|---|---|---|
| `tool.call` | Agent → 自身身份 | `null` |
| `agent.call` | 调用 Agent → 目标 Agent | `null` |
| `agent.result` | 目标 Agent → 调用 Agent | 原请求 `id` |
| `agent.handoff` | 原 Agent → 接管 Agent | `null` |
| `registry.publish` | Agent → Registry URL | `null` |
| `registry.rotate` | 当前 key → Registry URL | `null` |
| `registry.rotate.proof` | 新 key → Registry URL | 外层 rotate `id` |
| `registry.revoke` | Agent → Registry URL | `null` |

handoff 没有返回 envelope。模型 streaming token 不逐块签名；stream 中真实发生的 tool、Agent-as-tool 和 handoff 边界照常签名。

## Registry mutation payload

- publish：`agent_id`、`endpoint`、`capabilities`、`kid`、`public_key`。
- rotate：`agent_id`、`new_kid`、`new_public_key`、`proof`。外层必须由 Registry 当前 key 签名；proof 必须由新 key 签名且 `reply_to` 指向外层。
- revoke：仅 `agent_id`，由当前 key 签名。

Registry 在一个 `BEGIN IMMEDIATE` 事务内消费 nonce、检查 namespace/owner、更新 Agent/key history 并写成功审计。kid 全局不可复用，已撤销 Agent 不可重新发布。

## Agent ID

格式为 `agent://<host>/<one-or-more-segments>`。拒绝 userinfo、query、fragment、空段、歧义编码、反斜杠和 Agent ID 端口。production 仅接受公共 DNS host，并要求 endpoint 为 HTTPS 且 host 与 Agent ID 完全相同。local 仅接受 `agent://localhost/...` 和 loopback endpoint。

Golden vector 见 [`protocol-v1-vectors.json`](protocol-v1-vectors.json)。任何不兼容变更必须使用新的 `v`，不能静默改变 v1。
