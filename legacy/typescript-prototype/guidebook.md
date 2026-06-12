# Agent Identity SDK 运行逻辑说明

本文档从“程序是怎么跑起来的”视角说明整个 SDK 的结构、调用链路和本地 demo 行为。  
如果你后续要把它扩展成正式产品，这份文档可以作为第一版工程导览。

## 1. 设计目标

这个项目要解决的是“一个 Agent 如何向另一个 Agent 证明自己是谁”。

当前实现采用三层信任链：

1. `agent_id` 声明身份，例如 `agent://localhost:3001/weather`
2. 域名或主机在 `/.well-known/agent.json` 发布元数据
3. 请求携带私钥签名，接收方用元数据中的公钥验签

这样可以同时满足：

- 身份发现：知道目标 Agent 的 endpoint、公钥、组织、能力
- 抗伪造：只有持有私钥的一方能生成合法签名
- 可审计：每次请求都能还原出明确的 `agent_id` 和 `kid`
- 可轮换：通过 `kid`、`keys` 和 `revoked_kids` 支持密钥替换

## 2. 代码结构

### [src/types.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/types.ts)

定义整个 SDK 的公共类型：

- `AgentMetadata`：`agent.json` 的结构
- `Signer`：签名器抽象
- `NonceStore`：防重放存储抽象
- `SignRequestInput` / `VerifyRequestInput`：签名与验签入参
- `VerifyRequestResult`：统一结果和错误码

它的作用是把模块间的协议约定固定下来，后续增加适配器时不容易跑偏。

### [src/identity.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/identity.ts)

负责 `agent_id` 的解析与校验。

核心逻辑：

- `parseAgentId()`：把 `agent://domain/name` 拆成 `domain` 和 `name`
- `buildAgentId()`：根据 `domain` 和 `name` 生成标准格式
- `assertDomainMatch()`：确保 `agent_id` 里的域名与 metadata 发布域一致

这一步是整个信任链的第一层。如果域名绑定不成立，后面的公钥再正确也不可信。

### [src/metadata.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/metadata.ts)

负责身份发现。

核心逻辑：

1. 根据 `agent_id` 推导出 `/.well-known/agent.json` 的地址
2. 发起 HTTP 请求拉取 metadata
3. 校验 metadata 字段是否合法
4. 校验 metadata 的 `domain` 与 `agent_id` 一致
5. 做内存缓存和 `ETag` 复用
6. 根据 `kid` 找到当前可用公钥

关键点：

- 默认正式环境用 `https://{domain}/.well-known/agent.json`
- 本地 `localhost` 演示允许走 `http://`
- metadata 拉取失败时，如果本地缓存还有效，会回退到旧缓存

### [src/crypto.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/crypto.ts)

负责签名材料本身。

包含三类能力：

- `generateKeyPair()`：生成 Ed25519 密钥对
- `LocalKeySigner`：用本地 PEM 私钥签名
- `verifySignature()`：用 metadata 中的公钥验签

这里选 Ed25519 的原因很直接：

- Node 原生支持好
- 签名短
- 不需要复杂参数
- 很适合 SDK 和 demo 起步

### [src/auth.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/auth.ts)

这是最核心的模块，负责“签什么”和“怎么验”。

#### 4.1 canonical request

发送方和接收方都要构造同一份签名原文：

```text
METHOD
PATH_WITH_QUERY
SHA256(body)
x-agent-id:{agent_id}
x-agent-kid:{kid}
x-agent-timestamp:{timestamp}
x-agent-nonce:{nonce}
host:{host}
```

为什么要这样做：

- `METHOD` 防止别人把 `POST` 改成 `GET`
- `PATH_WITH_QUERY` 防止改目标路由
- `SHA256(body)` 防止改请求体
- `agent_id` 绑定调用者身份
- `kid` 指向具体公钥
- `timestamp + nonce` 防重放
- `host` 防止把签名请求转投到别的主机

#### 4.2 signRequest()

发送方流程：

1. 校验 `agent_id`
2. 从 `Signer` 里拿到 `kid`
3. 生成或复用 `timestamp` 和 `nonce`
4. 构造 canonical request
5. 用私钥签名
6. 把签名相关头写回 headers

最终会产生这些 header：

- `x-agent-id`
- `x-agent-kid`
- `x-agent-timestamp`
- `x-agent-nonce`
- `x-agent-signature-input`
- `x-agent-signature`

#### 4.3 verifyRequest()

接收方流程：

1. 读取并校验签名头是否齐全
2. 校验 `agent_id`
3. 校验 `timestamp` 是否在允许窗口内
4. 检查 `nonce` 是否已经被使用过
5. 通过 `resolveAgent()` 拉取远端 metadata
6. 根据 `kid` 找到有效公钥
7. 重建 canonical request
8. 验签
9. 验签成功后把 `nonce` 写入存储

注意最后一步必须在验签成功后执行。  
否则攻击者可以用无效请求批量污染 nonce 存储。

### [src/nonce.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/nonce.ts)

当前实现是 `MemoryNonceStore`。

运行逻辑很简单：

- 内部用 `Map<string, expiresAt>`
- `has()` 和 `set()` 前都顺手清掉过期项
- 单进程内可完成基本 replay 防护

局限性也很明显：

- 多实例服务之间不能共享
- 进程重启后 nonce 历史会丢失

所以它适合 demo 和测试，不适合生产。

### [src/adapters.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/adapters.ts)

这是给业务方省事的适配层。

当前提供：

- `createSignedFetch()`：把普通 `fetch` 包成自动签名版
- `verifyNodeRequest()`：简化 Node HTTP 请求的验签调用
- `attachMcpAuthHeaders()`：为未来 MCP 头注入预留一个最小工具函数

### [src/index.ts](D:/FDU/agent_auth/legacy/typescript-prototype/src/index.ts)

只是统一导出入口，没有业务逻辑。  
调用方通常只需要从这里 import 即可。

## 3. 一次完整请求是怎么跑通的

这里以 demo 为例说明。

### 第一步：发布方暴露 metadata

[demos/publisher-agent.ts](D:/FDU/agent_auth/legacy/typescript-prototype/demos/publisher-agent.ts) 启动一个本地 HTTP 服务。

它暴露两个地址：

- `/.well-known/agent.json`
- `/api/agent`

其中真正和身份发现有关的是：

- `http://localhost:3001/.well-known/agent.json`

这个文档里包含：

- `agent_id`
- `domain`
- `organization`
- `endpoint`
- `capabilities`
- `keys`
- `revoked_kids`

### 第二步：调用方对请求签名

[demos/send-request.ts](D:/FDU/agent_auth/legacy/typescript-prototype/demos/send-request.ts) 会：

1. 加载本地私钥
2. 组装请求 body
3. 调用 `signRequest()`
4. 把生成的 header 带到 HTTP 请求里
5. 将请求发给 `verifier-agent`

这里的关键点是：

- 发送时真正访问的是 `http://localhost:3002/invoke`
- 但签名时逻辑 URL 用的是 `https://localhost:3002/invoke`

这样设计是为了模拟“正式环境下应签 HTTPS 地址”，同时不妨碍本地 demo 用 HTTP 跑通。

### 第三步：验证方验签

[demos/verifier-agent.ts](D:/FDU/agent_auth/legacy/typescript-prototype/demos/verifier-agent.ts) 收到请求后会：

1. 收集完整 body
2. 规范化 headers
3. 调用 `verifyRequest()`
4. 根据结果返回 `200` 或 `401`

`verifyRequest()` 内部会继续做两件关键事情：

- 去 `publisher-agent` 拉取 `/.well-known/agent.json`
- 使用 metadata 中的公钥完成验签

如果通过，就能拿到结构化身份结果：

- `agentId`
- `kid`
- `organization`
- `capabilities`

这就是业务侧真正需要的“谁在调用我”的上下文。

## 4. 密钥轮换是怎么工作的

本项目的轮换是通过三部分共同完成的：

1. 请求头中的 `x-agent-kid`
2. metadata 里的 `keys`
3. metadata 里的 `revoked_kids`

默认情况下：

- 发布方使用 `2026-06-11-main`
- metadata 里公布主 key 的公钥

当设置：

```powershell
$env:AGENT_ROTATE="1"
```

发布方会改成：

- 激活 `2026-06-11-rotated`
- 把 `2026-06-11-main` 放入 `revoked_kids`

于是会出现两个结果：

- 老签名仍然数学上正确，但因为 `kid` 已吊销，所以被拒绝
- 新签名使用新私钥，metadata 也能找到对应公钥，因此验签通过

这正是正式系统里最常见的轮换语义。

## 5. 测试文件在验证什么

[tests/sdk.test.ts](D:/FDU/agent_auth/legacy/typescript-prototype/tests/sdk.test.ts) 目前覆盖 6 类行为：

1. `agent_id` 构造与解析
2. canonical request 输出稳定
3. 完整签名 + 验签成功路径
4. 重复 nonce 被判定为 replay
5. 吊销的 `kid` 被拒绝
6. metadata 域名与 `agent_id` 不一致时被拒绝

这些测试的意义在于：

- 保证核心协议不被无意改坏
- 让后续重构时有基础安全回归保护

## 6. 为什么当前实现能“实用测试”

它已经满足一个最小但完整的认证闭环：

- 有标准身份格式
- 有标准发布位置
- 有远端发现
- 有签名
- 有验签
- 有重放保护
- 有缓存
- 有轮换
- 有本地双 Agent 联调

所以它不仅是“能看”的设计稿，而是已经具备了真实测试价值的原型。

## 7. 当前边界与后续扩展建议

当前明确没有做的事情：

- 没有接真实 KMS
- 没有接 Redis `NonceStore`
- 没有做完整 JSON Schema 校验库接入
- 没有做 Express / Fastify 中间件
- 没有做完整 MCP / A2A / OpenAI Agents SDK 适配

如果你下一步继续扩展，推荐顺序是：

1. 增加 Redis `NonceStore`
2. 增加 Express/Fastify 验签中间件
3. 增加 metadata schema 校验库
4. 增加 KMS signer
5. 增加 MCP / A2A 示例

## 8. 运行命令回顾

安装依赖：

```bash
npm install
```

运行测试：

```bash
npm test
```

构建：

```bash
npm run build
```

启动 demo：

```bash
npm run demo:publisher
npm run demo:verifier
npm run demo:request
```

轮换演示：

```powershell
$env:AGENT_ROTATE="1"; npm run demo:publisher
$env:AGENT_ROTATE="1"; npm run demo:request
```

## 9. 一句话总结

这个 SDK 的运行本质是：

“调用方用私钥对请求签名，接收方根据 `agent_id` 去对方域名拉取公钥，再用公钥验签，并结合 `timestamp + nonce` 防止重放。”
