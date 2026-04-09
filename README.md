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
- **机场管理**：Web UI 一键添加/删除代理机场订阅，自动转换节点格式、生成策略组、修改 Surge 配置；内置定时更新与 Basic Auth 文件服务
- **流量异常下钻**：点击总览趋势图的任意时间柱，弹出该小时（或当天）的域名/设备上传排行，快速定位流量突增原因
- **灵活时间筛选**：今天 / 近 7 天 / 近 30 天 / 本月 / 自定义区间

## Dashboard 页面

| 路由 | 说明 |
|------|------|
| `/` | 全屋总览：汇总流量、趋势图（可点击下钻）、设备 TOP、域名 TOP，有高危告警时显示红色横幅 |
| `/devices` | 设备列表：流量排行，含代理 / 直连分量，支持直接改名 |
| `/device/<mac>` | 设备详情：趋势图、策略规则组饼图、TOP 域名 |
| `/domains` | 域名列表 |
| `/domain/<host>` | 域名详情：访问该域名的设备分布 |
| `/policies` | 策略分析：规则组饼图 + 排行 |
| `/policy_group/<name>` | 策略组详情：相关域名和设备 |
| `/airports` | 机场管理：查看已订阅机场列表、添加/删除机场、手动刷新节点 |
| `/sub/<name>_surge.txt` | 节点文件服务（内网免认证，外网需 Basic Auth） |
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
  ├── update_airports.py → 每 6h 自动刷新机场订阅节点
  └── web.py (Flask :8866)
        ├── Dashboard + AI 分析 + 可疑域名管理 API
        └── 机场管理 + 节点文件服务 (/sub/)
```

## 部署备注

当前实际部署采用 Docker Compose：
- Compose 项目目录：`/data/surge-monitor`
- 源码目录：`/programHost/surge-traffic-collector`
- 容器通过 bind mount 将 `/programHost/surge-traffic-collector` 挂载到容器内 `/app`
- Compose 通过 `/programHost/surge-traffic-collector/.env` 向容器注入运行配置，不应在 `docker-compose.yml` 内写入明文密钥

也就是说：
- 代码修改应在 `/programHost/surge-traffic-collector` 完成
- 容器编排、镜像构建和重启应在 `/data/surge-monitor` 执行

宿主机上虽然保留了历史 `systemd` unit，但当前应以 Docker Compose 部署为准。

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
   - 裸 IP 访问（非内网）→ LOW（大多为正常 APP 连接）
   - 数字占比 > 80% 且标签长度 ≥ 10 → HIGH（避免 UUID 子域名误报）
   - 子域名层级 > 6 → MEDIUM（疑似 DNS 隧道）
   - 域名总长 > 80 字符 → MEDIUM
   - 可疑 TLD（.tk/.top/.xyz/.buzz/.gq/.ml/.cf/.ga/.pw/.click/.surf/.icu）→ LOW

2. **本地黑名单**（URLhaus 恶意软件域名 → HIGH；StevenBlack 广告追踪 → LOW）

**自动白名单机制：**
- 新域名命中 `trusted_parent_domains` → 直接以 dismissed=1 入库，不出现在告警列表
- 裸 IP 查 ASN 后命中 `trusted_asns` → 同上自动 dismiss
- 内网 IP（RFC 1918 / loopback / link-local）完全跳过检测

## 部署

### 依赖

```bash
pip install -r requirements.txt
apt install sshpass   # 仅在仍使用密码方式拉取 SQLite 时需要
```

建议使用 MySQL 8.0.19+，并开启分区支持。

### 配置

```bash
cp config.example.py config.py
# 将实际值放入环境变量或 .env，config.py 只负责读取
cp .env.example .env
```

配置项说明：

```bash
# Surge 所在机器
SURGE_HOST=192.168.x.x
SURGE_SSH_USER=your_username
SURGE_SSH_KEY_PATH=/root/.ssh/id_ed25519
# 或回退到密码文件 / 环境变量（二选一）
SURGE_SSH_PASS_FILE=/root/.config/surge-ssh.pass
SURGE_SSH_PASS=
SURGE_API_KEY=your_surge_api_key
SURGE_API_LOCAL_PORT=16679
SURGE_API_REMOTE_PORT=16678

# SQLite 日文件路径（Mac 上的完整路径）
SURGE_SQLITE_PATH="/Users/xxx/Library/.../TrafficStatData/Session"

# MySQL
MYSQL_HOST=127.0.0.1
MYSQL_USER=root
MYSQL_PASS=your_mysql_password
MYSQL_DB=surge_traffic
DB_POOL_MAX_CONNECTIONS=10

# OpenRouter AI（不需要可留空）
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=minimax/minimax-m2.7
```

推荐将这些值放入项目目录下的 `.env` 文件；`config.py` / `config.example.py` 会自动读取。由于旧版 `config.py` 可能已经暴露过明文凭据，迁移后请自行轮换相关密码和 API Key。

### 从旧版本升级

如果你是从旧版直接升级到当前版本，建议按下面顺序执行：

```bash
cp .env.example .env
# 编辑 .env，填入你的真实配置
pip install -r requirements.txt
python3 upgrade.py
python3 ensure_request_partitions.py
```

`upgrade.py` 会自动完成以下结构升级：
- 创建 `trusted_parent_domains` / `trusted_asns` / `ip_asn_cache` / `ai_review_jobs`
- 给 `suspicious_domains` 补持久性统计列和索引
- 给 `requests` 补 `(remote_host, start_date)` 组合索引
- 补齐 `collector_state` 缺失的默认键

完成后再重启 `collector.py` 和 `web.py` 对应的 systemd 服务。

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

SCP 拉取 SQLite 建议优先使用 SSH key；只有在无法改造为 key 认证时，才使用 `SURGE_SSH_PASS_FILE` / `SURGE_SSH_PASS` 回退。

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

**分区自动维护**：建议每月执行一次：

```bash
python3 ensure_request_partitions.py
```

该脚本会补齐 `requests` 表未来数月的月分区，避免新数据长期落入 `p_future`。

## 机场管理

通过 Web UI 管理 Surge 代理机场订阅，自动完成节点转换、策略组生成和配置同步。

### 工作流程

**添加机场：**
1. 在 `/airports` 页面输入机场名称和原始订阅链接
2. 系统通过本地 subconverter 将订阅转换为 Surge 格式
3. 自动修复已知格式问题（hysteria→hysteria2、参数间距等）
4. 生成 9 个策略组（select / urltest / 6 个地区节点 / OpenAI 专用）
5. 将新机场注册到所有聚合策略组（故障转移、节点选择、手动切换等）
6. 同时更新内网版和公网版 Surge 配置文件

**删除机场：**
- 一键删除节点文件、从所有策略组中移除引用、清理配置文件

### 节点文件服务

Flask 在 `/sub/<name>_surge.txt` 提供节点文件下载，Surge 的 `policy-path` 直接指向此地址：
- **内网**：`http://<host>:8866/sub/<name>_surge.txt`（免认证）
- **公网**：通过反向代理 + Basic Auth 暴露，Surge 支持在 URL 中嵌入认证信息

### 自动更新

容器内 cron 每 6 小时运行 `update_airports.py`，刷新所有 `auto_update=true` 的机场节点。

### 配置

在 `.env` 中添加：

```bash
# subconverter 地址（用于订阅转换）
SUBCONVERTER_URL=http://127.0.0.1:25500
# 节点文件存储目录（需在 docker-compose.yml 中挂载）
SUB_STORE_PATH=/data/sub-store
# Surge 配置文件目录和文件名
SURGE_CONF_DIR=/Users/xxx/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents
SURGE_CONF_INTERNAL=your-config.conf
SURGE_CONF_PUBLIC=your-config-public.conf
# 节点文件的 URL 基路径
AIRPORT_INTERNAL_BASE=http://127.0.0.1:8866/sub
AIRPORT_PUBLIC_BASE=https://user:pass@your-domain.com/files
# 文件服务 Basic Auth（外网访问时需要）
AIRPORT_FILE_AUTH_USER=surge
AIRPORT_FILE_AUTH_PASS=your_password
```

Docker Compose 需要挂载存储目录：

```yaml
volumes:
  - /data/sub-store:/data/sub-store
```

## AI 功能

需要 [OpenRouter](https://openrouter.ai) API Key，在 `config.py` 中配置。

| 入口 | 说明 |
|------|------|
| 设备详情页「AI 分析」| 分析该设备的访问习惯和异常 |
| 总览页「AI 分析」| 全屋流量安全分析 |
| 安全页「🤖 AI 审查」| 批量审查当前告警，自动 dismiss 误报，支持选择模型 |

不需要此功能可忽略 `OPENROUTER_*` 配置项，仅 AI 相关按钮会报错，其余功能不受影响。

## 安全加固

- **SSH 操作**：使用 `sshpass -f` 临时密码文件（0600 权限），不再在命令行明文传递密码；`subprocess` 以列表参数调用，禁止 shell 注入
- **文件服务**：`/sub/<filename>` 路由对解析后的路径做 `resolve()` + 边界校验，防止路径穿越
- **认证**：Basic Auth 使用 `hmac.compare_digest()` 常量时间比较，记录失败日志
- **响应头**：自动添加 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy`
- **前端**：消除所有 inline `onclick` 事件处理器，改用 `data-*` 属性 + 事件委托，避免 XSS
