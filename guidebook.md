# Python Agent Identity SDK Guidebook

这个项目的目标不是做一个演示性质的脚本，而是交付一套可以发行给厂商接入的 Python SDK。SDK 负责三件事：发布 Agent 身份、发起带签名的 Agent 调用、验证远端 Agent 身份。围绕这三件事，仓库里还提供了一个真实软件 `LLM Agent Gateway`，用来做端到端验证，而不是停留在协议层自测。

## 1. 系统角色

- `agent_identity_sdk/`：正式 SDK 主线，厂商应该依赖这里提供的 API 和 CLI。
- `examples/gateway/`：真实网关应用，负责发布 `/.well-known/agent.json`、接收签名请求、验签、防重放、调用 LLM、记录审计日志。
- `pytests/`：单元测试、集成测试和网关端到端测试。
- `legacy/typescript-prototype/`：旧版 TypeScript 原型，仅保留作协议参考。

## 2. 身份发布逻辑

每个 Agent 通过 `/.well-known/agent.json` 发布自己的公开身份。当前项目约定的目标发布地址是：

- `http://192.144.228.237:8010/.well-known/agent.json`：测试 profile 下的直接访问地址。
- `http://192.144.228.237/.well-known/agent.json` 或 `https://192.144.228.237/.well-known/agent.json`：后续通过反向代理映射后的正式入口。

发布流程如下：

1. 使用 `agent-id keygen` 生成 Ed25519 密钥对。
2. 使用 `agent-id render-metadata` 渲染标准 `agent.json`。
3. 使用 `agent-id serve-well-known` 或 `examples/gateway` 暴露 `/.well-known/agent.json`。
4. 其他 Agent 通过 `resolve_agent()` 自动发现并拉取 metadata。

## 3. 调用与验签逻辑

Agent 调用时，SDK 会构造一段固定 canonical request，然后使用私钥签名，并把结果写入以下请求头：

- `X-Agent-Id`
- `X-Agent-Kid`
- `X-Agent-Timestamp`
- `X-Agent-Nonce`
- `X-Agent-Signature`
- `X-Agent-Signature-Input`

验签端会执行下面这条完整链路：

1. 读取签名头。
2. 校验时间窗。
3. 检查 nonce 是否已被使用。
4. 根据 `X-Agent-Id` 推导 `/.well-known/agent.json` 的拉取地址。
5. 校验 metadata 中的 host、key、吊销状态和时间有效期。
6. 重建 canonical request。
7. 用 metadata 里的公钥验签。
8. 返回结构化身份结果给上层业务。

## 4. 真实应用验证逻辑

`examples/gateway/` 不是玩具 demo，它是这套 SDK 的真实验证载体。它的工作流是：

1. 启动时自动准备密钥和 metadata。
2. 通过 `GET /.well-known/agent.json` 对外发布身份。
3. 通过 `POST /invoke` 接收带签名的 Agent 请求。
4. 用 SDK 验签并记录审计日志。
5. 验签成功后把请求转发到 OpenAI 兼容接口。
6. 返回 LLM 结果和已经确认过的 Agent 身份摘要。

当前示例默认对接：

- LLM Base URL：`https://yunwu.ai/`
- 模型：`gpt-4o-mini`

## 5. 为什么区分 `test` 与 `strict`

这套 SDK 同时服务于联调和生产接入，因此保留两种运行 profile：

- `test`：允许 `http`、允许 `IP:port`，适合本地联调和服务器 IP 测试。
- `strict`：要求 `https`、更严格的时钟漂移和 host 规则，适合正式环境。

这样做的原因是：`192.144.228.237` 这种直接 IP 发布方式非常适合当前阶段快速打通真实链路，但未来厂商正式接入时仍然建议迁移到域名加 HTTPS。

## 6. 推荐验证流程

推荐按下面顺序做一次完整验证：

1. `python -m venv .venv`
2. `.venv\\Scripts\\activate`
3. `pip install -e .[dev]`
4. `agent-id keygen`
5. `agent-id render-metadata --host 192.144.228.237:8010 --agent-name llm-gateway --endpoint http://192.144.228.237:8010/invoke --public-key-pem-path runtime/keys/public_key.pem`
6. 设置 `AGENT_GATEWAY_LLM_API_KEY`
7. `python -m examples.gateway.run`
8. `python -m examples.gateway.caller`
9. 访问 `/audit/recent` 查看审计日志。

## 7. 部署到 192.144.228.237 的建议

当前代码已经具备直接迁移到 Linux 主机的条件。部署时建议：

- 进程监听 `0.0.0.0:8010`
- 对外发布 host 使用 `192.144.228.237:8010`
- 如果你要把 `/.well-known/agent.json` 固定到 `192.144.228.237/.well-known/agent.json`，可以再加一层 Nginx 或 Caddy，把 80/443 入口转发到 8010

这样可以同时满足：

- SDK 联调阶段的快速验证
- 后续对外稳定发布的入口约束
