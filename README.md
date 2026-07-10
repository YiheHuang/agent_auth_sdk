# Agent Auth SDK

`agent-auth-sdk` 为 Agent 提供可验证身份、Registry 公钥发现、HTTP/消息签名验签、原子 nonce 防重放和 Vault Transit 私钥托管。

当前版本：`0.1.0b1`。这是允许协议与 API 调整的 beta 版本。

## 安装

```bash
pip install agent-auth-sdk

# 按需安装
pip install "agent-auth-sdk[vault]"
pip install "agent-auth-sdk[redis]"
pip install "agent-auth-sdk[openai]"
```

Registry 是独立发行包：

```bash
pip install agent-auth-registry
```

## 十分钟快速开始

### 1. Registry 管理员创建 developer 和 namespace

```bash
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin grant-namespace \
  --client-id developer-a \
  --domain agents.example.com \
  --path-prefix /team-a
```

保存首次命令输出的 API key。Registry v1 必须以单 worker 运行，并放在 HTTPS 反向代理之后。

### 2. 从 Vault 创建并发布 Agent

```python
import os

from agent_auth_sdk import AgentInstance, RegistryClient


def registry_credential() -> str:
    # 示例；生产环境请替换为 secret manager credential provider。
    return os.environ["AGENT_REGISTRY_API_KEY"]

agent = AgentInstance.from_vault(
    domain="agents.example.com",
    name="team-a/weather",
    organization="Example Lab",
    endpoint="https://agents.example.com/weather/invoke",
    vault_addr="https://vault.example.com",
    vault_token_file="/run/secrets/vault-token",
    transit_mount="transit",
    key_name="weather-agent",
)

async with RegistryClient(
    base_url="https://registry.example.com",
    client_id="developer-a",
    api_key=registry_credential,
) as registry:
    await registry.publish(agent.metadata, signer=agent.signer)
```

### 3. 验证签名消息

```python
from agent_auth_sdk import AgentVerifier, MetadataResolverConfig

async with AgentVerifier(
    resolver_config=MetadataResolverConfig(
        registry_url="https://registry.example.com",
    ),
) as verifier:
    result = await verifier.verify_message(
        message=incoming_message,
        expected_recipient="agent://agents.example.com/team-a/resolver",
    )
    if not result.ok:
        raise PermissionError(f"{result.code}: {result.reason}")
```

## 安全边界

- Registry 管理员是 developer namespace 的信任根；beta v1 不执行 DNS challenge。
- 配置 Registry 后默认失败关闭，不会因 Registry 故障静默改用不可信域名发现。
- Metadata capability 是经过认证的声明，不等同于业务授权；授权由应用策略决定。
- OpenAI `call_local_agent()` 保护同进程编排完整性，不提供进程隔离；真实网络边界使用 `RemoteAgentClient` 和 `AgentAuthASGIMiddleware`。
- 私钥保留在 Vault Transit；SDK 只读取公钥并请求指定 key version 签名。

完整威胁模型见 [SECURITY_MODEL.md](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md)。

## 文档

- [SDK 使用指南](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SDK_GUIDE.md)
- [安全模型](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md)
- [自定义协议 v1](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/PROTOCOL_V1.md)
- [Registry 运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)
- [OpenAI Agents 集成](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/OPENAI_AGENTS.md)

## 开发验证

```bash
python -m pytest -q
python -m build
python -m build packages/agent-auth-registry
python -m twine check --strict dist/* packages/agent-auth-registry/dist/*
```

## License

MIT
