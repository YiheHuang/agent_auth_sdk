# Examples

| 文件 | 展示内容 | 外部服务 |
|---|---|---|
| `openai_local.py` | direct、FunctionTool、Agent-as-tool、handoff | 无；确定性 Model |
| `vault_registry.py` | Vault/Registry 检查与发布 | 按 production 配置 |
| `remote_server.py` | `AgentAuth.endpoint()` | 按配置 |
| `remote_client.py` | `remote_tool()` | 按配置 |

```bash
pip install -e ".[server]"
python examples/openai_local.py
```

框架无关调用使用 `await auth.call("source", "target", payload)`。完整配置见 `QUICKSTART.md` 与 `docs/CONFIGURATION.md`。示例不包含 token、API key 或私钥。
