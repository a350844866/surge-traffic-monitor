# Surge Traffic Monitor

全屋网络流量采集与可视化系统。通过 Surge HTTP API 实时采集每一条网络请求，结合 Surge 自带的 SQLite 每日聚合数据，存入 MySQL，并提供一个多维度的 Web Dashboard。

## 功能概览

- **实时采集**：每 30 秒轮询 Surge `/v1/requests/recent`，逐条入库，不丢数据
- **每日聚合同步**：每小时 SCP 拉取 Surge SQLite 日统计文件，作为数据安全网
- **设备识别**：从 Surge `/v1/devices` 同步设备名称、厂商、IP，MAC 地址映射为可读名称；支持在 Dashboard 直接改名并同步回 Surge
- **策略规则组**：将底层节点名（如 `[SS] 🇭🇰 HK 04`）映射为有意义的规则组（如 `🚀 节点选择`、`🤖 Claude`）
- **AI 流量分析**：对单设备或全屋流量调用 LLM，SSE 流式输出分析报告
- **可疑域名检测**：启发式规则（高 Shannon 熵 / 裸 IP / DGA 特征）+ 本地黑名单双层检测，自动标记高危 / 中危 / 低危条目
- **智能白名单**：信任父域名表 + 信任 ASN 机构表，命中则自动 dismiss；裸 IP 通过 ip-api.com 查 ASN 后自动匹配信任机构
- **AI 一键审查**：点击按钮让 AI 批量审查当前告警，自动 dismiss 误报、保留真正可疑项，支持切换模型
- **灵活时间筛选**：今天 / 近 7 天 / 近 30 天 / 本月 / 自定义区间

## Dashboard 页面

| 路由 | 说明 |
|------|------|
| `/` | 全屋总览：汇总流量、趋势图、设备 TOP、域名 TOP，有告警时显示红色横幅 |
| `/devices` | 设备列表：流量排行，含代理 / 直连分量，支持直接改名 |
| `/device/<mac>` | 设备详情：趋势图、策略规则组饼图、TOP 域名 |
| `/domains` | 域名列表 |
| `/domain/<host>` | 域名详情：访问该域名的设备分布 |
| `/policies` | 策略分析：规则组饼图 + 排行 |
| `/policy_group/<name>` | 策略组详情：相关域名和设备 |
| `/suspicious` | 可疑域名：筛选排序、ASN 分析、AI 一键审查、白名单管理 |

## 系统架构

```
Mac mini (Surge 运行中)
  ├── Surge HTTP API  :16678 (127.0.0.1 only)
  └── SQLite 日统计文件  ~/Library/.../TrafficStatData/Session/YYYYMMDD.sqlite
          │
          │  SSH 隧道 / SCP
          ▼
Linux 服务器
  ├── collector.py      → MySQL surge_traffic（每 30s 采集 + 每 5min 设备同步）
  ├── detector.py       → 可疑域名检测（随采集器每 30s 自动运行）
  ├── update_blocklist.py → 每天 03:00 更新域名黑名单（URLhaus + StevenBlack）
  └── web.py (Flask :8866)
        └── Dashboard + AI 分析 + 可疑域名管理 API
```

## 数据库表结构

| 表 | 说明 |
|----|------|
| `requests` | 细粒度每请求记录，按月分区，ROW_FORMAT=COMPRESSED |
| `daily_traffic` | 每日聚合数据，来自 SQLite |
| `devices` | MAC → 设备名称映射 |
| `collector_state` | 采集进度状态（last_request_id 等）|
| `suspicious_domains` | 可疑域名检测结果，dismissed=1 为白名单 |
| `domain_blocklist` | 本地域名黑名单（URLhaus + StevenBlack，~8.7 万条）|
| `trusted_parent_domains` | 信任父域名列表，匹配则新域名自动 dismiss |
| `trusted_asns` | 信任 ASN/机构列表，裸 IP 归属可信机构则自动 dismiss |
| `ip_asn_cache` | IP → ASN/机构查询缓存（30 天有效）|

## 可疑域名检测

**两层检测，每 30 秒自动运行：**

1. **启发式规则**（`detector.py`）
   - Shannon 熵 > 4.5 且标签长度 ≥ 8 → HIGH（疑似 DGA）
   - 裸 IP 访问（非内网）→ MEDIUM
   - 数字占比 > 60% → HIGH
   - 子域名层级 > 6 → MEDIUM（疑似 DNS 隧道）
   - 域名总长 > 80 字符 → MEDIUM
   - 可疑 TLD（.tk/.top/.xyz 等）→ LOW

2. **本地黑名单**（URLhaus 恶意软件域名 → HIGH；StevenBlack 广告追踪 → LOW）

**自动白名单机制：**
- 新域名命中 `trusted_parent_domains` → 直接以 dismissed=1 入库，不出现在告警列表
- 裸 IP 查 ASN 后命中 `trusted_asns` → 同上自动 dismiss
- 内网 IP（192.168.x / 10.x / 172.16.x）完全跳过检测

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

# OpenRouter AI（用于流量分析和可疑域名 AI 审查，不需要可留空）
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

**黑名单自动更新**（`/etc/systemd/system/surge-blocklist-update.timer`，每天 03:00 运行）：

```bash
systemctl enable --now surge-collector.timer surge-dashboard.service surge-blocklist-update.timer
```

Dashboard 默认监听 `:8866`。

## AI 功能

需要 [OpenRouter](https://openrouter.ai) API Key，在 `config.py` 中配置。

| 入口 | 说明 |
|------|------|
| 设备详情页「AI 分析」| 分析该设备的访问习惯和异常 |
| 总览页「AI 分析」| 全屋流量安全分析 |
| 安全页「🤖 AI 审查」| 批量审查当前告警，自动 dismiss 误报，支持选择模型 |

不需要此功能可忽略 `OPENROUTER_*` 配置项，仅 AI 相关按钮会报错，其余功能不受影响。
