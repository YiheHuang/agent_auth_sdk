# Agent Auth 安全模型

## 信任根

1. Registry 管理员为 developer 创建凭证并分配精确 domain/path namespace。
2. Registry 的 HTTPS 证书保护 developer API key 和发布响应。
3. Vault Transit 保存 Agent 私钥；SDK 读取指定版本公钥并请求签名。
4. 接收方从配置的 Registry 获取发送方公钥，并在本地验证签名。

Registry v1 不执行 DNS challenge。管理员在分配 namespace 前必须通过组织流程确认 domain 归属。

## 已防御威胁

- 未授权 developer 抢注或覆盖其他 developer 的 Agent identity。
- API key 单独泄漏后修改既有 Agent key。
- HTTP body、消息 payload、recipient、timestamp 和签名字段篡改。
- 单进程、Redis 和 Registry SQLite 中的并发 nonce 重放。
- 直接 Metadata 发现中的 userinfo、IPv4/IPv6 私网地址、localhost、重定向和 DNS rebinding；请求连接到校验后钉住的 IP，并保留原 Host/TLS SNI。
- 重复、撤销或错误 P-256 key，以及不明确的 PEM/DER key material。

## 不提供的保证

- Metadata capability 是发送方/Registry 认证的声明，不自动构成业务授权。
- 同进程 OpenAI local wrapper 无法隔离恶意 Agent 代码或被攻陷的 Python 进程。
- 单节点 SQLite Registry 不提供高可用、多 worker 或跨地域一致性。
- Registry 管理员、Vault 管理员或宿主机被攻陷不在 v1 防御范围内。
- 自定义协议 v1 不是 RFC 9421 或 JWS；跨语言实现必须遵循固定测试向量。

## 攻击者与残余风险

- 网络攻击者可以观察、延迟和重放流量，但在 TLS、签名和原子 nonce 正确部署时不能伪造身份。
- 获得 developer API key 但没有当前 Agent 私钥的攻击者不能覆盖既有 ownership 或完成密钥证明。
- 获得 Agent Vault token 的攻击者可以在 token 有效期和权限范围内冒充该 Agent；应立即撤销 token、
  rotate key、发布新 metadata，并在应用授权层暂时禁用该 Agent。
- Registry 管理员可以分配 namespace，Vault 管理员可以控制签名 key；两者都属于显式信任角色，
  不能由 SDK 的应用级校验消除。
- 签名认证不防止已认证 Agent 发送恶意业务 payload；请求 schema、资源限制和业务授权仍由应用负责。

## TLS、代理与日志

- strict Agent endpoint 和 Registry/Vault 必须使用 HTTPS。
- Nginx 等代理后面的接收端必须配置外部 `public_base_url`，避免内部 host/scheme 与发送端签名不一致。
- 只有明确可信的代理地址可以设置转发 header；Uvicorn 不应直接暴露公网。
- 日志可以记录 agent_id、kid、错误 code、request ID 和耗时，不得记录 Vault token、developer API key、
  私钥、完整签名或默认记录业务 payload。

## 可用性与恢复

- nonce store 和 Registry 可用性是失败关闭的一部分；依赖故障可能拒绝合法调用，这是预期安全行为。
- 单进程接收端可使用内存 nonce store；多实例必须使用共享原子 store，否则重放保护只在实例内有效。
- Registry 备份包含身份、namespace 和审计信息，应加密、限制权限并定期执行恢复演练。

## 安全默认值

- strict profile：HTTPS、公共 DNS identity、Registry 失败关闭。
- `registry_only`：配置 Registry 后的默认发现模式。
- `registry_then_direct`：仅在应用显式接受绕过 Registry 信任根的风险时启用。
- Registry：单 worker、loopback 监听、HTTPS proxy、非 root systemd 用户。

## 漏洞报告

不要在公开 issue 中提交可利用细节。请通过仓库所有者提供的私密安全渠道报告，并包含受影响版本、复现条件和建议缓解措施。
