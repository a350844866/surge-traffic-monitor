# Surge Traffic Collector Configuration
# Copy this file to config.py and fill in your values.

# SSH / Surge API
SURGE_HOST = "192.168.x.x"           # IP of your Mac running Surge
SURGE_SSH_USER = "your_username"
SURGE_SSH_PASS = "your_ssh_password"
SURGE_API_KEY = "your_surge_api_key"
SURGE_API_LOCAL_PORT = 16679   # local tunnel port -> 127.0.0.1:16678 on Mac mini
SURGE_API_REMOTE_PORT = 16678
SURGE_SQLITE_PATH = "/Users/your_username/Library/Application Support/com.nssurge.surge-mac/TrafficStatData/Session"

# MySQL
MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = 3306
MYSQL_USER = "root"
MYSQL_PASS = "your_mysql_password"
MYSQL_DB   = "surge_traffic"

# OpenRouter AI
OPENROUTER_API_KEY = "sk-or-v1-your_openrouter_api_key"
OPENROUTER_MODEL = "minimax/minimax-m2.7"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

# Collector behavior
DEVICE_SYNC_INTERVAL = 300   # sync devices every N seconds
SQLITE_SYNC_INTERVAL = 3600  # sync SQLite every N seconds
