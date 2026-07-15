# SDK 使用指南

本指南按实际任务组织。完整参数和返回类型见 [API Reference](API_REFERENCE.md)，协议细节见 [协议 v1](PROTOCOL_V1.md)。

## 1. 身份与 signer

Agent identity 固定为：

```text
agent://{normalized-domain}/{path}
```

domain 使用小写 IDNA；path segment 只允许字母、数字、`.`、`_`、`~` 和 `-`。生产 strict profile 拒绝 IP、localhost、私网及保留地址。

生产环境使用 Vault：

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.from_vault(
    domain="agents.example.com",
    name="team/weather",
    organization="Example Lab",
    endpoint="https://agents.example.com/team/weather/invoke",
    vault_addr="https://vault.example.com",
    vault_token_file="/run/secrets/vault-token",
    transit_mount="transit",
    key_name="weather-agent",
    capabilities=["weather.read"],
)
```

`from_vault()` 会读取 P-256 公钥、固定当前 Vault key version，并验证 sign 权限。默认不会创建 key。`vault_token_file` 必须只有一行 token，POSIX 权限建议 `0600`。

自定义 KMS 实现 `Signer` Protocol，再使用 `AgentInstance.from_signer()`；`LocalEs256Signer` 仅应出现在测试或示例中。

## 2. 发布身份

管理员必须先创建 developer 并分配覆盖该 agent_id 的 namespace。应用使用 `RegistryClient`：

```python
import os
from agent_auth_sdk import RegistryClient

async with RegistryClient(
    base_url="https://registry.example.com",
    client_id="developer-a",
    api_key=lambda: os.environ["AGENT_REGISTRY_API_KEY"],
) as registry:
    await registry.publish(agent.metadata, signer=agent.signer)
```

credential provider 可同步或异步返回 API key，避免长期把 raw token 放在对象或配置 repr 中。`AgentInstance.publish()` 是等价的便捷入口，但参数中的 `registry_url` 必须是完整 publish endpoint。

## 3. 签名和验证消息

```python
from agent_auth_sdk import AgentVerifier, MetadataResolverConfig

message = await sender.sign_message(
    payload={"order_id": "o-42"},
    recipient=receiver.agent_id,
    message_type="order.review",
)

async with AgentVerifier(
    resolver_config=MetadataResolverConfig(registry_url="https://registry.example.com"),
) as verifier:
    result = await verifier.verify_message(
        message=message,
        expected_recipient=receiver.agent_id,
    )

if not result.ok:
    raise PermissionError(f"{result.code}: {result.reason}")
```

点对点消息总是传入 `recipient` 和 `expected_recipient`。第一次成功验签会原子消费 nonce；同一消息再次提交返回 `NONCE_REPLAYED`。

## 4. 签名和验证 HTTP

对实际发送的 bytes 签名，不要在签名后重新序列化 JSON：

```python
from agent_auth_sdk.http_utils import canonical_json_bytes

body = canonical_json_bytes({"task": "review"})
signature = await sender.sign_http(
    method="POST",
    url="https://receiver.example.com/invoke",
    body=body,
    headers={"content-type": "application/json"},
)
response = await http_client.post(url, content=body, headers=signature.headers)
```

接收端可直接调用 `AgentVerifier.verify_http()`，或使用 `AgentAuthASGIMiddleware`。Middleware 验签成功后把 `VerificationSuccess` 写到 `request.state.agent_auth`，并拒绝超过 `max_body_bytes` 的请求。

完整双进程程序见 [`examples/remote_agent`](../examples/remote_agent)。

## 5. 认证之后执行授权

metadata capability 是签名声明，不等于业务权限：

```python
from agent_auth_sdk import AuthorizationPolicy, VerificationSuccess

class AllowWeatherReaders:
    async def authorize(self, result: VerificationSuccess, *, capability: str | None = None) -> bool:
        return bool(result.metadata and capability in result.metadata.capabilities)

authorized = await verifier.authorize(
    result,
    policy=AllowWeatherReaders(),
    capability="weather.read",
)
```

策略异常会失败关闭并返回 `POLICY_REJECTED`。

## 6. Metadata 发现与缓存

```python
from agent_auth_sdk import DiscoveryMode, FileMetadataCache, MetadataResolverConfig

resolver = MetadataResolverConfig(
    registry_url="https://registry.example.com",
    discovery_mode=DiscoveryMode.REGISTRY_ONLY,
)
cache = FileMetadataCache("runtime/metadata-cache.sqlite3")
```

- 配置 Registry 后默认 `REGISTRY_ONLY`，故障或 404 时失败关闭。
- `DIRECT_ONLY` 必须明确接受直接发现信任边界。
- `REGISTRY_THEN_DIRECT` 会在 Registry 失败后访问 identity domain，只应显式启用。
- `FileMetadataCache` 适合单机持久缓存；自定义缓存实现 `MetadataCache`。

## 7. Nonce store

`InMemoryNonceStore` 只适合一个 Python 进程。多个 worker/实例共享接收流量时：

```python
from redis.asyncio import Redis
from agent_auth_sdk import RedisNonceStore

nonce_store = RedisNonceStore(Redis.from_url("redis://redis.internal:6379/0"))
```

自定义实现只需提供原子 `consume(key, ttl_seconds) -> bool`。不得用分离的 `has()`/`set()` 替代。

## 8. 密钥生命周期

- `add_key()`：增加额外 active key，不改变当前 signer。
- `rotate_key()`：新 key 成为当前 signer，旧 current key 变为 inactive。
- `revoke_key()`：永久将非当前 kid 加入黑名单；kid 不可复用。
- `revoke_agent()`：不可逆撤销整个 Agent。

rotate/add 同时要求当前 key 签完整请求、新 key 签 possession proof。当前 signing key 必须先 rotate 才能 revoke。示例见 [`examples/key_lifecycle.py`](../examples/key_lifecycle.py)。

## 9. CLI

```bash
agent-auth init \
  --project-root . \
  --roles coordinator,security \
  --framework openai-agents \
  --mode local

agent-auth integrate-openai-agents \
  --project-root . \
  --roles coordinator,security \
  --role-capability security:review.security

agent-auth doctor --config .agent-auth/agent-auth.toml
```

`init`/`integrate-openai-agents` 创建 `.agent-auth/` scaffold，并在路径未被占用时新增可直接导入的
`agent_auth_adapter.py`；不会覆盖现有 adapter 或修改现有业务源码。`doctor` 是只读检查，不创建
key、不发布 Agent。

`1.0.0rc1` 提供职责分离命令：

```bash
# 只读扫描已有 OpenAI Agents 项目
agent-auth openai inspect .

# 生成幂等迁移清单，不改业务源码
agent-auth openai migrate . --write

# 在受控部署步骤中创建/检查 key 并发布单个身份
agent-auth provision --identity coordinator --config .agent-auth/agent-auth.toml
```

应用运行时使用 `OpenAIAgentAuth.from_env(identity="coordinator")`，不会隐式执行 provision。

## 10. 错误处理

不可信输入的验签入口返回 `VerificationSuccess | VerificationFailure`，不要依赖异常文本：

```python
if not result.ok:
    logger.info("agent authentication rejected", extra={"code": result.code})
```

配置错误、无效本地参数、网络 `raise_for_status()` 和 Vault 权限错误仍会抛异常。不要把 Registry API key、Vault token、签名原文或完整异常凭证写入日志。
