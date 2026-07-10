# Agent Auth 自定义签名协议 v1

## 编码

- 文本统一使用 UTF-8。
- Base64 使用无 padding 的 base64url。
- JSON 对象按 key 排序，使用紧凑分隔符，拒绝非字符串 key、NaN 和 Infinity。
- timestamp 必须是 UTC RFC 3339 秒级格式：`YYYY-MM-DDTHH:MM:SSZ`。
- ES256 使用 P-256、SHA-256 和 ASN.1 DER ECDSA signature。
- key fingerprint 是 SubjectPublicKeyInfo DER 的 SHA-256 hex。

测试向量见 [`protocol-v1-vectors.json`](protocol-v1-vectors.json)。

## HTTP canonical request

按换行拼接：

```text
METHOD
/path?query
BODY_SHA256_BASE64URL
x-agent-id:...
x-agent-kid:...
x-agent-timestamp:...
x-agent-nonce:...
host:...
```

必需 headers：`x-agent-id`、`x-agent-kid`、`x-agent-timestamp`、`x-agent-nonce`、`x-agent-signature`、`x-agent-signature-input` 和 `host`。

`x-agent-signature-input` 必须精确等于：

```text
method path body-digest x-agent-id x-agent-kid x-agent-timestamp x-agent-nonce host
```

HTTP SDK 对实际发送的 body bytes 计算摘要；使用 dict/list convenience API 时先生成上述 canonical JSON bytes。

## Signed Agent message

消息 canonical string 使用域分离前缀 `agent-message-v1`，随后依次包含 agent_id、kid、timestamp、nonce、payload_type、payload digest、recipient 和 message_type。

点对点调用必须传 `expected_recipient`，且消息 recipient 必须存在并完全匹配。

## Registry 写协议

Registry publish、rotate、add-key 使用独立 canonical 前缀和 signature-input，避免跨操作重放。完整请求签名覆盖实际发送的 canonical JSON body bytes；服务端使用接收到的原始 body bytes 验签，不会重新序列化后替代。rotate/add-key 同时要求 current key 签名完整请求和 new key 签名 proof。

## 版本策略

v1 canonical 格式冻结。未来 RFC 9421/JWS 支持通过新的协议版本协商，不改变 v1 验证行为。
