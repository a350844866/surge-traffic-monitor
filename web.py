#!/usr/bin/env python3
"""
Surge Traffic Dashboard - Flask Web App
Port: 8866
"""

from flask import Flask

from routes.ai import bp as ai_bp
from routes.airports import bp as airports_bp
from routes.pages import bp as pages_bp
from routes.suspicious import bp as suspicious_bp
from routes.traffic import bp as traffic_bp
from web_common import ensure_ai_review_jobs_table, fmt_bytes

app = Flask(__name__)
app.jinja_env.globals["fmt_bytes"] = fmt_bytes

app.register_blueprint(traffic_bp)
app.register_blueprint(ai_bp)
app.register_blueprint(suspicious_bp)
app.register_blueprint(airports_bp)
app.register_blueprint(pages_bp)


if __name__ == "__main__":
    ensure_ai_review_jobs_table()
    app.run(host="0.0.0.0", port=8866, debug=False)
