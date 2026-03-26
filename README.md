# Surge Traffic Monitor

全屋网络流量采集与可视化系统。通过 Surge HTTP API 实时采集每一条网络请求，结合 Surge 自带的 SQLite 每日聚合数据，存入 MySQL，并提供一个多维度的 Web Dashboard。

## 功能概览

- **实时采集**：每 30 秒轮询 Surge `/v1/requests/recent`，逐条入库，不丢数据
- **每日聚合同步**：每小时 SCP 拉取 Surge SQLite 日统计文件，作为数据安全网
- **设备识别**：从 Surge `/v1/devices` 同步设备名称、厂商、IP，MAC 地址映射为可读名称
- **策略规则组**：将底层节点名（如 `[SS] 🇭🇰 HK 04`）映射为有意义的规则组（如 `🚀 节点选择`、`🤖 Claude`）
- **AI 流量分析**：对单设备或全屋流量调用 LLM，SSE 流式输出分析报告
- **灵活时间筛选**：今天 / 近 7 天 / 近 30 天 / 本月 / 自定义区间

## Dashboard 页面

| 路由 | 说明 |
|------|------|
| `/` | 全屋总览：汇总流量、趋势图、设备 TOP、域名 TOP |
| `/devices` | 设备列表：流量排行，含代理 / 直连分量 |
| `/device/<mac>` | 设备详情：趋势图、策略规则组饼图、TOP 域名 |
| `/domains` | 域名列表 |
| `/domain/<host>` | 域名详情：访问该域名的设备分布 |
| `/policies` | 策略分析：规则组饼图 + 排行 |
| `/policy_group/<name>` | 策略组详情：相关域名和设备 |

## 系统架构

```
Mac mini (Surge 运行中)
  ├── Surge HTTP API  :16678 (127.0.0.1 only)
  └── SQLite 日统计文件  ~/Library/.../TrafficStatData/Session/YYYYMMDD.sqlite
          │
          │  SSH 隧道 / SCP
          ▼
Linux 服务器
  ├── collector.py   → MySQL surge_traffic
  │     ├── 每 30s: 轮询 /v1/requests/recent
  │     ├── 每 5min: 同步 /v1/devices
  │     └── 每 1h:  SCP SQLite 日文件
  └── web.py (Flask :8866)
        └── Dashboard + AI 分析 API
```

## 数据库表结构

| 表 | 说明 |
|----|------|
| `requests` | 细粒度每请求记录，按月分区，ROW_FORMAT=COMPRESSED |
| `daily_traffic` | 每日聚合数据，来自 SQLite |
| `devices` | MAC → 设备名称映射 |
| `collector_state` | 采集进度状态（last_request_id 等）|

## 部署

### 依赖

```bash
pip install flask requests pymysql
apt install sshpass   # 用于 SCP 拉取 SQLite
```

MySQL 5.7+ / 8.0，需开启分区支持。

### 配置

```bash
cp config.example.py config.py
# 编辑 config.py，填入你的实际值
```

配置项说明：

```python
# Surge 所在机器
SURGE_HOST = "192.168.x.x"
SURGE_SSH_USER = "your_username"
SURGE_SSH_PASS = "your_ssh_password"
SURGE_API_KEY  = "your_surge_api_key"   # Surge HTTP API 的认证 key
SURGE_API_LOCAL_PORT  = 16679           # 本机 SSH 隧道端口
SURGE_API_REMOTE_PORT = 16678           # Surge 监听端口

# SQLite 日文件路径（Mac 上的完整路径）
SURGE_SQLITE_PATH = "/Users/xxx/Library/.../TrafficStatData/Session"

# MySQL
MYSQL_HOST = "127.0.0.1"
MYSQL_USER = "root"
MYSQL_PASS = "your_mysql_password"
MYSQL_DB   = "surge_traffic"

# OpenRouter AI（用于流量分析功能，不需要可留空）
OPENROUTER_API_KEY = "sk-or-v1-..."
OPENROUTER_MODEL   = "minimax/minimax-m2.7"
```

### 初始化数据库

```bash
mysql -u root -p < schema.sql
```

### Surge HTTP API 开启方式

在 Surge 配置文件 `[General]` 段加入：

```
http-api = YOUR_KEY@0.0.0.0:16678
```

如果 Surge 只绑定 `127.0.0.1`，需在 Linux 服务器上建 SSH 隧道：

```bash
ssh -N -L 16679:127.0.0.1:16678 user@192.168.x.x
```

### 以 systemd 运行

**采集器**（`/etc/systemd/system/surge-collector.service`）：

```ini
[Unit]
Description=Surge Traffic Collector

[Service]
ExecStart=/usr/bin/python3 /path/to/collector.py
User=root
Restart=on-failure
```

配合 timer 每 30 秒触发（`surge-collector.timer`）：

```ini
[Unit]
Description=Run Surge collector every 30s

[Timer]
OnBootSec=10
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
```

**Dashboard**（`/etc/systemd/system/surge-dashboard.service`）：

```ini
[Unit]
Description=Surge Traffic Dashboard

[Service]
ExecStart=/usr/bin/python3 /path/to/web.py
User=root
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now surge-collector.timer surge-dashboard.service
```

Dashboard 默认监听 `:8866`。

## AI 分析

需要 [OpenRouter](https://openrouter.ai) API Key，在 `config.py` 中配置。Dashboard 的设备详情页和总览页均有「AI 分析」入口，结果通过 SSE 流式输出，实时渲染 Markdown。

不需要此功能可忽略 `OPENROUTER_*` 配置项，仅分析按钮会报错，其余功能不受影响。
