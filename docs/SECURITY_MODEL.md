# 安全模型

## 信任链

1. Registry 管理员核验开发者后，为其分配不重叠的精确 domain/path namespace。
2. 开发者凭 Registry API key 提交写请求；Agent 当前 Vault key 对 mutation 签名。
3. Vault Transit 保存不可导出的 P-256 私钥，应用只获得指定 key/version 的签名权限。
4. 接收方从固定 Registry 解析当前公钥，在本地验证 SignedEnvelope、audience、时间和重放。
5. Registry、Vault 和远程 Agent endpoint 的 TLS 证书提供传输端点认证。

Registry v1 不做 DNS challenge；namespace 分配本身是管理员信任决策。

## 提供的保证

- 未获 namespace 的 developer 不能首次注册身份；已有 owner 不能被覆盖。
- Registry API key 单独泄漏不足以更新或轮换已有 Agent，因为还需要当前私钥签名。
- payload、sender、audience、kid、type、时间、request ID 和 reply correlation 均受签名保护。
- 本地 SQLite 与 Registry SQLite 通过唯一约束原子拒绝并发重放。
- Registry 解析失败时 production 调用失败关闭，不回退到 Agent 自报地址。
- 轮换需要当前 key 和新 key 双重证明；历史 kid 永久禁止复用。

## 不提供的保证

- capability 是已认证声明，不是授权结果；endpoint handler 必须依据 `AuthContext` 自行授权。
- 同进程 Agent 虽然完整签名验签，但不提供进程、内存或私钥权限隔离。
- 被攻陷的 Vault token 在撤销前可用于冒充对应 Agent。
- 被攻陷的 Registry/Vault 管理员或宿主机不在协议防御范围内。
- 单节点 SQLite Registry 不提供 HA、多 worker 或跨区域一致性。
- 签名不判断业务 payload 是否安全，也不替代 schema、资源限制和内容安全控制。

## 生产基线

- Registry 非 root、单 worker、仅监听 loopback，由 Nginx 提供 HTTPS。
- Agent ID、Registry、Vault 和 Agent endpoint 使用公共 DNS 与 HTTPS。
- Vault key version 固定；token/API key 来自环境变量或权限受限文件，不写入 TOML。
- 每个生产进程只配置它需要的身份；不同信任边界使用不同进程和 Vault token。
- state SQLite 放在持久化、仅服务用户可写的本地磁盘，禁止网络文件系统。
- 日志只记录 agent_id、kid、request ID、type 和稳定错误码；不得记录 token、API key、私钥、完整签名或默认记录 payload。

发现的漏洞请通过 [GitHub Security Advisory](https://github.com/YiheHuang/agent_auth_sdk/security/advisories/new) 私密提交。
