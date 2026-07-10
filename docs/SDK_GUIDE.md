# Agent Auth SDK 使用指南

## 主要入口

- `AgentInstance`：聚合 identity、metadata 和 signer。
- `RegistryClient`：集中管理 Registry URL、developer credential 和发布操作。
- `AgentVerifier`：集中管理 HTTP client、Metadata cache、nonce store 和验签配置。
- `RemoteAgentClient`：发送签名 HTTP 请求并验证对端签名响应。
- `AgentAuthASGIMiddleware`：在 ASGI handler 前验证 HTTP 签名。

`RegistryClient` 默认只接受 HTTPS；`allow_insecure_http=True` 仅用于 loopback/隔离测试环境。

## Identity

identity 格式为 `agent://{normalized-domain}/{path}`。domain 使用小写 IDNA；path segment 仅允许字母、数字、`.`、`_`、`~` 和 `-`。禁止 userinfo、query、fragment、百分号歧义路径和非法端口。

## Metadata 发现

```python
from agent_auth_sdk import DiscoveryMode, MetadataResolverConfig

config = MetadataResolverConfig(
    registry_url="https://registry.example.com",
    discovery_mode=DiscoveryMode.REGISTRY_ONLY,
)
```

配置 Registry 时默认 `REGISTRY_ONLY`。`REGISTRY_THEN_DIRECT` 必须显式启用；直接发现会拒绝私网/保留地址和重定向，并把连接钉到请求前校验通过的 DNS IP。

## 原子 nonce store

生产多实例 verifier 使用 `RedisNonceStore`。其核心接口为：

```python
await store.consume(key, ttl_seconds)  # 首次 True，重放 False
```

`InMemoryNonceStore` 只适合单进程测试或本地运行。

## Vault 生命周期

- 生产环境通过 `vault_token_file` 提供短期 token；文件必须只有一行非空 token，在 POSIX 上权限不得向 group/other 开放（建议 `0600`）。
- 推荐由 Vault Agent 或 AppRole 登录流程把短期 token 写入受保护文件，不在 TOML、日志或对象 repr 中保存 raw token。
- Vault 地址默认必须为 HTTPS；明文地址、raw token 和跳过 TLS 校验只允许显式 dev/test 模式。
- SDK 将 signer 固定到 Vault key version，默认 `kid` 含 `:vN`，避免 Vault 内部轮换后同一 kid 对应不同公钥。

## 身份与授权

验签成功只证明“该消息由 Registry 中该 Agent key 签发且内容未被修改”。应用仍需根据 authenticated agent_id、namespace 和自身策略进行授权。

实现 `AuthorizationPolicy.authorize()` 后，通过 `await verifier.authorize(result, policy=policy, capability="...")` 显式执行授权；策略异常按 `POLICY_REJECTED` 失败关闭。

## CLI

```bash
agent-auth init --project-root . --roles coordinator,worker --framework openai-agents
agent-auth doctor --config .agent-auth/agent-auth.toml
```

`doctor` 只读检查 identity、profile、TLS 策略和 Vault token 文件，不发布 Agent。
