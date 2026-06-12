# Agent Identity SDK

这个仓库现在的主线实现是一个真正可集成、可发行的 Python Agent 身份认证 SDK，并附带一个可运行的 `LLM Agent Gateway` 示例服务。

旧的 TypeScript 原型已经归档到 [legacy/typescript-prototype](D:/FDU/agent_auth/legacy/typescript-prototype)。

## 当前交付

- Python SDK：`agent_identity_sdk/`
- CLI：`agent-id`
- 示例服务：`examples/gateway/`
- Python 测试：`pytests/`
- 主线运行说明：`guidebook.md`
- 旧 TypeScript 原型：`legacy/typescript-prototype/`

## 能力概览

- `agent://host/name` 身份格式
- `/.well-known/agent.json` 身份发布与发现
- Ed25519 请求签名 / 验签
- `strict` / `test` 双运行 profile
- nonce 防重放
- metadata 缓存与 `ETag` 支持
- 本地内存与 Redis nonce 存储
- 文件型 metadata 缓存
- FastAPI 网关、审计日志和 OpenAI 兼容 LLM 转发

## 当前目标口径

这套 SDK 的目标已经明确为：

- 让开发者完成 Agent 身份发布
- 让调用方完成带签名的 Agent 调用
- 让服务方完成 Agent 验签与审计
- 把真实发布入口收敛到 `192.144.228.237/.well-known/agent.json`
- 用真实网关应用完成从签名请求到 LLM 响应的全流程验证

## 目录结构

- `agent_identity_sdk/`：正式 Python SDK 主线实现
- `examples/gateway/`：真实软件示例，包含 FastAPI 网关、审计与 LLM 转发
- `pytests/`：Python 单元测试、集成测试、端到端测试
- `legacy/typescript-prototype/`：早期 TypeScript 原型与说明文档
- `req.txt`：最初需求草案

## 路径说明

这次重构后，主线路径已经统一到 Python 结构：

- Python 入口包在 `agent_identity_sdk/`
- 示例服务入口在 `examples/gateway/run.py`
- 测试目录在 `pytests/`
- 旧 TS 代码不再占用根目录的 `src/`、`demos/`、`tests/`

我已经额外验证过两件事：

- `pytest` 全部通过
- `python -m agent_identity_sdk.cli --help` 能正常启动

这说明 Python 主线没有遗留导入路径问题。

## 快速开始

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
pytest
```

如果你之前激活过一个损坏的 `.venv`，先退出旧环境再重新创建：

```bash
deactivate
rmdir /s /q .venv
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
```

## 常用命令

生成密钥：

```bash
agent-id keygen
```

渲染 metadata：

```bash
agent-id render-metadata --host 192.144.228.237:8010 --agent-name llm-gateway --endpoint http://192.144.228.237:8010/invoke --public-key-pem-path runtime/keys/public_key.pem
```

启动网关：

```bash
set AGENT_PROFILE=test
set AGENT_GATEWAY_HOST=0.0.0.0
set AGENT_GATEWAY_AGENT_HOST=192.144.228.237:8010
set AGENT_GATEWAY_LLM_API_KEY=你的key
python -m examples.gateway.run
```

调用网关：

```bash
set AGENT_CALLER_URL=http://192.144.228.237:8010/invoke
set AGENT_CALLER_HOST=192.144.228.237:8010
python -m examples.gateway.caller
```

## 测试

```bash
pytest
```

## Legacy 说明

旧 TypeScript 原型保存在：

- [legacy/typescript-prototype](D:/FDU/agent_auth/legacy/typescript-prototype)
- 旧原型导览文档：[legacy/typescript-prototype/guidebook.md](D:/FDU/agent_auth/legacy/typescript-prototype/guidebook.md)

Python 主线运行逻辑说明见：

- [guidebook.md](D:/FDU/agent_auth/guidebook.md)
