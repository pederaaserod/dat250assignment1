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