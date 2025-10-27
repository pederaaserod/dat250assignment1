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