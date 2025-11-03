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
    ALLOWED_EXTENSIONS = {}  # TODO: Might use this at some point, probably don't want people to upload any file type
    WTF_CSRF_ENABLED = False  # TODO: I should probably implement this wtforms feature, but it's not a priority


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