"""Provides the configuration for the Social Insecurity application.

This file is used to set the configuration for the application.

Example:
    from flask import Flask
    from social_insecurity.config import Config

    app = Flask(__name__)
    app.config.from_object(Config)

    # Use the configuration
    secret_key = app.config["SECRET_KEY"]
"""

import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "secret"  # TODO: Use this with wtforms
    SQLITE3_DATABASE_PATH = "sqlite3.db"  # Path relative to the Flask instance folder
    UPLOADS_FOLDER_PATH = "uploads"  # Path relative to the Flask instance folder
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"} #allowed extensions
    WTF_CSRF_ENABLED = True  # TODO: I should probably implement this wtforms feature, but it's not a priority
    
    #Session managment og lockout tiers
    SESSION_ATTEMPT_LIMIT = 10
    SESSION_TIMEOUT = timedelta(minutes=30)
    SESSION_LOCK_DURATION = timedelta(minutes=5)

    LOCKOUT_THERESHOLD = 5
    LOCKOUT_TIERS=[
        timedelta(minutes=1),
        timedelta(minutes=5),
        timedelta(minutes=15),
        timedelta(hours=1),
]

 # Denial-of-Service protections
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8 MB max size of posts/uploads

    # Simple limiter defaults (used by in-process limiter)
    RATE_LIMIT_REQUESTS = 10     # allowed requests per window (per IP)
    RATE_LIMIT_WINDOW = 60        # seconds (sliding window)
    RATE_LIMIT_BLOCK_SECONDS = 300  # seconds to temporarily block IP when exceeded
