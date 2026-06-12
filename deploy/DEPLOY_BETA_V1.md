# Agent Identity SDK Beta v1.0 部署方案

目标：在 CentOS 服务器 `192.144.228.237` 上部署一个中心 registry，使 SDK 可以真正完成：

- 开发者发布 Agent metadata
- 外部读取统一 `/.well-known/agent.json`
- SDK 从中心仓库解析并验签

当前最小 beta 只部署一个服务：

- `registry`

服务代码位置：

- `agent_auth_registry/`

## 一、对外接口

- `GET http://192.144.228.237/.well-known/agent.json`
- `POST http://192.144.228.237/registry/agents`

## 二、服务器组件

- CentOS 7/8/9
- Python 3.11+
- nginx
- systemd

## 三、安装依赖

CentOS 8/9:

```bash
sudo dnf install -y python3 python3-pip nginx git
```

CentOS 7:

```bash
sudo yum install -y python3 python3-pip nginx git
```

如果系统 Python 太旧，建议自行安装 Python 3.11 后再继续。

## 四、部署目录

```bash
sudo mkdir -p /opt/agent_auth_sdk
sudo chown $USER:$USER /opt/agent_auth_sdk
git clone <你的仓库地址> /opt/agent_auth_sdk
cd /opt/agent_auth_sdk
```

## 五、安装项目

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .[dev]
pytest
```

要求：

- `pytest` 全部通过

## 六、准备运行目录

```bash
mkdir -p runtime/registry/.well-known
sudo mkdir -p /etc/agent-auth
```

## 七、配置 registry

```bash
sudo cp deploy/registry.env.example /etc/agent-auth/registry.env
sudo vi /etc/agent-auth/registry.env
```

建议配置：

```env
AGENT_REGISTRY_HOST=127.0.0.1
AGENT_REGISTRY_PORT=8008
AGENT_REGISTRY_PATH=/opt/agent_auth_sdk/runtime/registry/.well-known/agent.json
AGENT_REGISTRY_TOKEN=replace-with-strong-random-token
```

## 八、安装 systemd 服务

```bash
sudo cp deploy/registry.service /etc/systemd/system/registry.service
sudo systemctl daemon-reload
sudo systemctl enable registry.service
sudo systemctl start registry.service
sudo systemctl status registry.service
```

## 九、安装 nginx

```bash
sudo cp deploy/nginx.agent-auth.conf /etc/nginx/conf.d/agent-auth.conf
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl restart nginx
```

## 十、验证

先验证 registry 内部服务：

```bash
curl http://127.0.0.1:8008/healthz
curl http://127.0.0.1:8008/.well-known/agent.json
```

再验证公网入口：

```bash
curl http://192.144.228.237/healthz
curl http://192.144.228.237/.well-known/agent.json
```

## 十一、开发者发布验证

开发者机器上执行：

```bash
agent-auth-sdk keygen
agent-auth-sdk render-metadata --host demo.example.com --agent-name weather --endpoint https://demo.example.com/invoke --public-key-pem-path runtime/keys/public_key.pem
agent-auth-sdk publish-to-registry --metadata-path runtime/.well-known/agent.json --registry-url http://192.144.228.237/registry/agents --token <registry-token>
```

然后在服务器上确认：

```bash
curl http://192.144.228.237/.well-known/agent.json
```

再做解析验证：

```bash
agent-auth-sdk inspect-metadata agent://demo.example.com/weather --registry-url http://192.144.228.237/.well-known/agent.json
```

## 十二、Beta v1.0 发布门槛

- `pytest` 通过
- registry 服务可启动
- `/.well-known/agent.json` 可读
- `/registry/agents` 可写
- 至少 1 个 Agent 成功发布
- SDK 可从中心仓库解析该 Agent

## 十三、当前 beta 边界

当前适合 beta，不建议称为正式生产版，原因：

- registry 使用单 JSON 文件存储
- 发布鉴权是 token 级别
- 没有后台管理界面
- 没有高可用与多副本
