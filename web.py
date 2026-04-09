#!/usr/bin/env python3
"""
Surge Traffic Dashboard - Flask Web App
Port: 8866
"""

import hmac

from flask import Flask, jsonify, request

import config
from routes.ai import bp as ai_bp
from routes.airports import bp as airports_bp
from routes.pages import bp as pages_bp
from routes.suspicious import bp as suspicious_bp
from routes.traffic import bp as traffic_bp
from web_common import close_request_db, ensure_ai_review_jobs_table, fmt_bytes

app = Flask(__name__)
app.jinja_env.globals["fmt_bytes"] = fmt_bytes

app.teardown_appcontext(close_request_db)

# Sensitive endpoints that require API key when API_KEY is configured
_WRITE_PREFIXES = (
    "/api/airports",       # add/delete/refresh airports
    "/api/ai/",            # AI analysis (costs money)
    "/api/suspicious/",    # dismiss/scan/enrich
    "/api/trusted/",       # manage trusted lists
    "/api/device/",        # rename devices
)


@app.before_request
def check_api_key():
    """Require API key for write/sensitive endpoints when API_KEY is set."""
    if not config.API_KEY:
        return  # No key configured — open access
    # Skip auth for read-only pages and static assets
    path = request.path
    if not any(path.startswith(p) for p in _WRITE_PREFIXES):
        return
    # Allow GET on airports list and node-status (read-only)
    if request.method == "GET" and path in ("/api/airports",):
        return
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if key and hmac.compare_digest(key, config.API_KEY):
        return
    return jsonify({"error": "Unauthorized — set X-API-Key header"}), 401


app.register_blueprint(traffic_bp)
app.register_blueprint(ai_bp)
app.register_blueprint(suspicious_bp)
app.register_blueprint(airports_bp)
app.register_blueprint(pages_bp)


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found"}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal Server Error"}), 500


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


if __name__ == "__main__":
    ensure_ai_review_jobs_table()
    app.run(host="0.0.0.0", port=8866, debug=False)
