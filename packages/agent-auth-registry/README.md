# Agent Auth Registry

`verifiable-agent-auth-registry` 是 `verifiable-agent-auth-sdk` 的单节点中心身份注册服务。

它提供 developer namespace 管理、Agent metadata 发布、密钥生命周期、原子 nonce 防重放和公开身份解析端点。

```bash
pip install verifiable-agent-auth-registry
agent-auth-registry --help
agent-auth-registry-admin --help
```

Registry v1 仅支持单节点、单 worker SQLite 部署，并且必须置于 HTTPS 反向代理之后。

完整部署与安全说明见 [源码仓库](https://github.com/YiheHuang/agent_auth_sdk)。
