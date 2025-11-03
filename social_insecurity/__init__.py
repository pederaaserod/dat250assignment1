"""Provides the social_insecurity package for the Social Insecurity application.

The package contains the Flask application factory.
"""

from pathlib import Path
from shutil import rmtree
from typing import cast

import time
import threading
from collections import deque, defaultdict
import logging

from flask import Flask, current_app


from social_insecurity.config import Config
from social_insecurity.database import SQLite3

from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

#Flask-Limiter integration 
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _HAS_FLASK_LIMITER = True
except Exception:
    Limiter = None
    get_remote_address = None
    _HAS_FLASK_LIMITER = False

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# from flask_login import LoginManager
# from flask_bcrypt import Bcrypt
# from flask_wtf.csrf import CSRFProtect

sqlite = SQLite3()
# TODO: Handle login management better, maybe with flask_login?
login = LoginManager()
# TODO: The passwords are stored in plaintext, this is not secure at all. I should probably use bcrypt or something
bcrypt = Bcrypt()
# TODO: The CSRF protection is not working, I should probably fix that
csrf = CSRFProtect()

#class for simple rate limiter
class SimpleRateLimiter:
    """
    In-memory sliding-window limiter per IP with temporary block.
    Thread-safe using an internal lock.
    Not distributed — one instance per process.
    """
    def __init__(self, requests: int = 100, window: int = 60, block_seconds: int = 300):
        self.requests = int(requests)
        self.window = int(window)
        self.block_seconds = int(block_seconds)
        self.buckets = defaultdict(deque)  # ip -> deque[timestamps]
        self.blocked = {}  # ip -> unblock_time
        self.lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            # unblock expired entries
            unblock = self.blocked.get(ip)
            if unblock is not None:
                if now >= unblock:
                    del self.blocked[ip]
                else:
                    return False

            dq = self.buckets[ip]
            # drop timestamps outside window
            cutoff = now - self.window
            while dq and dq[0] <= cutoff:
                dq.popleft()

            if len(dq) >= self.requests:
                # exceed -> block temporarily
                self.blocked[ip] = now + self.block_seconds
                dq.clear()
                #logging info
                logger.info("Blocking IP %s for %s seconds", ip, self.block_seconds)
                return False

            dq.append(now)
            return True

    def reset(self, ip: str) -> None:
        with self.lock:
            self.buckets.pop(ip, None)
            self.blocked.pop(ip, None)



def create_app(test_config=None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.from_object(test_config)

    sqlite.init_app(app, schema="schema.sql")
    login.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    # login.init_app(app)
    # bcrypt.init_app(app)
    # csrf.init_app(app)
    
    #Initialize SimpleRateLimiter instance (always present), if not found in config it uses the numbers as default
    limiter = SimpleRateLimiter(
        requests=app.config.get("RATE_LIMIT_REQUESTS", 10),
        window=app.config.get("RATE_LIMIT_WINDOW", 60),
        block_seconds=app.config.get("RATE_LIMIT_BLOCK_SECONDS", 300),
    )

    with app.app_context():
        create_uploads_folder(app)

    @app.cli.command("reset")
    def reset_command() -> None:
        """Reset the app."""
        instance_path = Path(current_app.instance_path)
        if instance_path.exists():
            rmtree(instance_path)

    with app.app_context():
        import social_insecurity.routes  # noqa: E402,F401

    return app


def create_uploads_folder(app: Flask) -> None:
    """Create the instance and upload folders."""
    upload_path = Path(app.instance_path) / cast(str, app.config["UPLOADS_FOLDER_PATH"])
    if not upload_path.exists():
        upload_path.mkdir(parents=True)
