import time
import threading
from collections import deque, defaultdict
from social_insecurity import sqlite
from flask_login import UserMixin
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def get(user_id):
        user = sqlite.query(f"SELECT * FROM Users WHERE id = ?;", user_id, one=True)
        if user:
            return User(user["id"], user["username"])
        return None
    
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