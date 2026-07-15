# Agent Auth Wire Protocol v1

本文是 v1 的规范性说明。关键词 MUST、MUST NOT、SHOULD 和 MAY 按 RFC 2119 含义理解。v1 在
Agent Auth 1.x 中保持字节级兼容。

## 通用编码

- 文本 MUST 为 UTF-8。
- Base64 MUST 使用无 padding 的 base64url。
- 时间 MUST 为 UTC RFC 3339 秒级 `YYYY-MM-DDTHH:MM:SSZ`；不得包含小数秒或非 UTC offset。
- nonce MUST 在一次签名中唯一，接收方 MUST 原子消费并在有效窗口内拒绝重复值。
- v1 算法 MUST 为 ES256：P-256、SHA-256、ASN.1 DER ECDSA signature。
- 公钥与 fingerprint MUST 基于 P-256 SubjectPublicKeyInfo DER；fingerprint 为 SHA-256 hex。

JSON canonicalization：对象 key 按 Unicode code point 排序，UTF-8 输出，分隔符为 `,` 和 `:`，
不得输出多余空白。key MUST 是字符串；NaN、Infinity 和不可序列化值 MUST 被拒绝。

## Agent identity

```text
agent://<normalized-host>/<one-or-more-path-segments>
```

不得包含 userinfo、query、fragment、空 path segment、百分号编码或反斜杠。DNS host 使用小写
IDNA ASCII；端口必须有效。strict profile 只接受公共 DNS host，不接受 IP、localhost、`.local`
或 `.internal`。

## HTTP 请求签名

签名输入按 LF (`0x0A`) 连接，末尾不增加 LF：

```text
METHOD
/raw-path?raw-query
BODY_SHA256_BASE64URL
x-agent-id:<value>
x-agent-kid:<value>
x-agent-timestamp:<value>
x-agent-nonce:<value>
host:<value>
```

- METHOD MUST 转为大写。
- path/query MUST 使用实际发送的编码形式；无 query 时不得附加 `?`。
- body digest MUST 对实际发送的原始 body bytes 计算。
- host MUST 与目标 URL authority 一致，包括非默认端口。
- header 名大小写不敏感，但每个签名相关 header MUST 恰好出现一次。

必需 header：

```text
x-agent-id
x-agent-kid
x-agent-timestamp
x-agent-nonce
x-agent-signature
x-agent-signature-input
host
```

`x-agent-signature-input` MUST 精确为：

```text
method path body-digest x-agent-id x-agent-kid x-agent-timestamp x-agent-nonce host
```

接收端 MUST 在签名验证成功后原子消费 nonce。失败请求不得被当作已认证上下文交给业务代码。

反向代理部署 MUST 使用外部可见 origin 重建 canonical URL，且只能信任来自明确代理地址的转发信息。

## SignedAgentMessage

消息签名使用域分离前缀 `agent-message-v1`，随后按实现固定顺序包含：agent_id、kid、timestamp、
nonce、payload_type、canonical payload digest、recipient 和 message_type。

点对点调用：

- sender MUST 写入 recipient。
- receiver MUST 显式传入 expected recipient。
- 两者 MUST 完全相等，否则返回 `RECIPIENT_MISMATCH`。
- 转发、payload 修改、message_type 修改或第二次消费 nonce MUST 失败。

## Registry 写操作

publish、rotate、add-key、revoke-key 和 revoke-agent 使用不同域分离前缀，防止签名跨操作复用。
签名覆盖实际 canonical JSON body bytes。rotate/add-key 同时要求 current key 对请求签名，以及 new key
对 possession proof 签名。

Registry MUST 在同一个写事务中完成 nonce 消费、namespace/ownership 校验、metadata/key 更新和审计。
首次 ownership MUST 使用仅插入语义，冲突返回 409，不得改写 owner。

## 稳定失败分类

常用 code：`INVALID_AGENT_ID`、`MESSAGE_INVALID`、`SIGNATURE_INVALID`、`TIMESTAMP_EXPIRED`、
`NONCE_REPLAYED`、`RECIPIENT_MISMATCH`、`KEY_NOT_FOUND`、`KEY_REVOKED`、
`METADATA_FETCH_FAILED`、`POLICY_REJECTED`。

面对不可信输入的验签入口 MUST 返回稳定失败，不得泄漏 Pydantic、密钥解析或时间解析异常。

## 测试向量与版本演进

Golden vectors 见 [`protocol-v1-vectors.json`](protocol-v1-vectors.json)。第三方实现必须验证 canonical
bytes、body digest、DER signature、fingerprint、timestamp 和 recipient 篡改用例。

未来 RFC 9421/JWS 支持必须使用新的协议版本协商，不得静默改变 v1。
