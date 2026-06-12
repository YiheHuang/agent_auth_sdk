# Beta v1.0 Release Checklist

## 1. 代码与测试

- 本地执行 `pytest`
- 确认 `agent-id --help` 正常
- 确认 `examples.registry.run` 可启动

## 2. 服务器准备

- 服务器：`192.144.228.237`
- 安装 Python 3.11+
- 安装 `nginx`
- 创建服务用户 `agentauth`
- 创建目录 `/opt/agent_auth_sdk`
- 创建目录 `/etc/agent-auth`

## 3. Registry 上线

- 安装 `deploy/registry.service`
- 配置 `/etc/agent-auth/registry.env`
- 启动 `registry.service`
- 验证 `http://127.0.0.1:8008/healthz`
- 验证 `http://127.0.0.1:8008/.well-known/agent.json`

## 4. Nginx 上线

- 安装 `deploy/nginx.agent-auth.conf`
- 执行 `nginx -t`
- 重载 `nginx`
- 验证 `http://192.144.228.237/.well-known/agent.json`
- 验证 `http://192.144.228.237/registry/agents`

## 5. 开发者发布链路

- 本地生成 metadata
- 调用 `agent-id publish-to-registry`
- 在中心 `/.well-known/agent.json` 中确认条目存在

## 6. 验签链路

- 使用 `agent-id inspect-metadata` 从中心仓库成功解析 Agent
- 使用 SDK 测试完成签名与验签

## 7. Beta 发布门槛

- 中心注册表可读
- 注册接口可写
- 至少 1 个开发者 Agent 成功发布
- SDK 可从中心仓库解析并完成验证
- 服务可重启恢复
- registry 文件持久化未丢失
