# Examples

- `openai_local.py`：无需 Vault、Registry 或 API key，实际运行 direct、FunctionTool、Agent-as-tool 和 handoff。
- `vault_registry.py`：读取生产 `agent-auth.toml`，检查 Vault/Registry 后发布身份。
- `remote_server.py` / `remote_client.py`：签名请求、验签 endpoint、签名响应和 remote tool。

运行：

```bash
pip install -e ".[server]"
python examples/openai_local.py
```

远程示例需要先准备生产配置并分别为调用方和接收方进程提供自己的配置文件。
