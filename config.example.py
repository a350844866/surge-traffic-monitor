import os

try:
    from dotenv import load_dotenv
except ImportError:  # optional in local bootstrap flows
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


def _get_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _get_float(name, default):
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _get_bool(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# SSH / Surge API
SURGE_HOST = os.getenv("SURGE_HOST", "127.0.0.1")
SURGE_SSH_USER = os.getenv("SURGE_SSH_USER", "")
SURGE_SSH_PASS = os.getenv("SURGE_SSH_PASS", "")
SURGE_SSH_PASS_FILE = os.getenv("SURGE_SSH_PASS_FILE", "")
SURGE_SSH_KEY_PATH = os.getenv("SURGE_SSH_KEY_PATH", "")
SURGE_SSH_PORT = _get_int("SURGE_SSH_PORT", 22)
SURGE_SSH_DISABLE_STRICT_HOST_KEY_CHECKING = _get_bool(
    "SURGE_SSH_DISABLE_STRICT_HOST_KEY_CHECKING",
    True,
)
SURGE_API_KEY = os.getenv("SURGE_API_KEY", "")
SURGE_API_LOCAL_PORT = _get_int("SURGE_API_LOCAL_PORT", 16679)
SURGE_API_REMOTE_PORT = _get_int("SURGE_API_REMOTE_PORT", 16678)
SURGE_SQLITE_PATH = os.getenv(
    "SURGE_SQLITE_PATH",
    "/Users/your_username/Library/Application Support/com.nssurge.surge-mac/TrafficStatData/Session",
)

# MySQL
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = _get_int("MYSQL_PORT", 3306)
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASS = os.getenv("MYSQL_PASS", "")
MYSQL_DB = os.getenv("MYSQL_DB", "surge_traffic")

# Shared DB client behavior
DB_CONNECT_TIMEOUT = _get_int("DB_CONNECT_TIMEOUT", 10)
DB_CONNECT_RETRIES = _get_int("DB_CONNECT_RETRIES", 3)
DB_CONNECT_RETRY_DELAY = _get_float("DB_CONNECT_RETRY_DELAY", 5.0)
DB_POOL_MAX_CONNECTIONS = _get_int("DB_POOL_MAX_CONNECTIONS", 10)
DB_POOL_MIN_CACHED = _get_int("DB_POOL_MIN_CACHED", 1)
DB_POOL_MAX_CACHED = _get_int("DB_POOL_MAX_CACHED", 5)

# OpenRouter AI
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "minimax/minimax-m2.7")
OPENROUTER_BASE_URL = os.getenv(
    "OPENROUTER_BASE_URL",
    "https://openrouter.ai/api/v1/chat/completions",
)

# Collector behavior
DEVICE_SYNC_INTERVAL = _get_int("DEVICE_SYNC_INTERVAL", 300)
SQLITE_SYNC_INTERVAL = _get_int("SQLITE_SYNC_INTERVAL", 3600)
BLOCKLIST_UPDATE_INTERVAL = _get_int("BLOCKLIST_UPDATE_INTERVAL", 86400)
REQUEST_PARTITION_MONTHS_AHEAD = _get_int("REQUEST_PARTITION_MONTHS_AHEAD", 6)

# Airport (subscription) management
SUBCONVERTER_URL = os.getenv("SUBCONVERTER_URL", "http://127.0.0.1:25500")
SUB_STORE_PATH = os.getenv("SUB_STORE_PATH", "/data/sub-store")
SURGE_CONF_DIR = os.getenv(
    "SURGE_CONF_DIR",
    "/Users/your_username/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents",
)
SURGE_CONF_INTERNAL = os.getenv("SURGE_CONF_INTERNAL", "your-config.conf")
SURGE_CONF_PUBLIC = os.getenv("SURGE_CONF_PUBLIC", "your-config-public.conf")
AIRPORT_INTERNAL_BASE = os.getenv("AIRPORT_INTERNAL_BASE", "http://127.0.0.1:8866/sub")
AIRPORT_PUBLIC_BASE = os.getenv("AIRPORT_PUBLIC_BASE", "")
AIRPORT_FILE_AUTH_USER = os.getenv("AIRPORT_FILE_AUTH_USER", "surge")
AIRPORT_FILE_AUTH_PASS = os.getenv("AIRPORT_FILE_AUTH_PASS", "")
