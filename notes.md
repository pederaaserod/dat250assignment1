# Notes Assignment 2

## Changes:

### __init__.py

```py
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

login = LoginManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()
...
def create_app(...):
    ...
    login.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    ...
```




## 6. Cryptography
 
 - pip install argon2-cffi
 - from argon2 import PasswordHasher
 - ph = PasswordHasher()
 - ph.hash(<pword>), ph.verify(<hash>, <input_pword>)




1. Enable CSRF (WTF_CSRF_ENABLED = True) and ensure SECRET_KEY is set from env.

2. Add MAX_CONTENT_LENGTH and ALLOWED_EXTENSIONS to config.

3. Add server-side upload checks and UUID filename prefix in stream.

4. Add if user is None: abort(404) handling where user lookups are performed.

5. Remove debug prints and add login_user(..., remember=...).

6. Add small validators (Length) to long text fields.

7. Add a small @app.after_request to set security headers.

8. Consider adding imghdr or Pillow-based content checks and rate limiting for login.