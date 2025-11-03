"""Provides all routes for the Social Insecurity application.

This file contains the routes for the application. It is imported by the social_insecurity package.
It also contains the SQL queries used for communicating with the database.
"""

from pathlib import Path
from flask import current_app as app
from flask import flash, redirect, render_template, send_from_directory, url_for, session, request,jsonify
from flask_login import login_user, logout_user, current_user
from werkzeug.utils import secure_filename
from social_insecurity.models import User
from social_insecurity import sqlite, bcrypt
from social_insecurity.forms import CommentsForm, FriendsForm, IndexForm, PostForm, ProfileForm
from social_insecurity.config import Config
from datetime import datetime, timedelta, timezone
import uuid

#imports for file uploading
import os
import time
import uuid
from werkzeug.utils import secure_filename

#allowed files from config
def allowed_file(filename):
    allowed_extensions = app.config["ALLOWED_EXTENSIONS"]
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


@app.route("/", methods=["GET", "POST"])
@app.route("/index", methods=["GET", "POST"])
def index():
    """Provides the index page for the application.

    It reads the composite IndexForm and based on which form was submitted,
    it either logs the user in or registers a new user.

    If no form was submitted, it simply renders the index page.
    """
    index_form = IndexForm()
    login_form = index_form.login
    register_form = index_form.register
    print(login_form.validate_on_submit(), register_form.validate_on_submit())
    if login_form.validate_on_submit() and login_form.submit.data:
        get_user = f"""
            SELECT *
            FROM Users
            WHERE username = ?;
            """
        user = sqlite.query(get_user, login_form.username.data, one=True)

        if user is None:
            flash("Sorry, this user does not exist!", category="warning")
            record_session_failure()
        elif bcrypt.check_password_hash(user["password"], login_form.password.data):
            login_user(User(user["id"], user["username"]))
            flash("Sorry, wrong password!", category="warning")
            record_session_failure()
        else:
            reset_session_counter()
            session["username"] = login_form.username.data
            return redirect(url_for("stream", username=current_user.username))
    

    elif register_form.validate_on_submit() and register_form.submit.data:
        if user is None:
            flash("Sorry, this user does not exist!", category="warning")
        insert_user = """
            INSERT INTO Users (username, first_name, last_name, password)
            VALUES (?, ?, ?, ?);
            """
        sqlite.query(
        insert_user, 
        register_form.username.data,
        register_form.first_name.data,
        register_form.last_name.data,
        register_form.password.data,
        )

        sess = session.get("login", {})
        locked_until = sess.get("locked_until")
        if locked_until:
            locked_until_dt = datetime.fromisoformat(locked_until)
        if locked_until_dt > datetime.now(timezone.utc):
            flash("Too many failed login attempts. Please try again later.", category="warning")
            return render_template("index.html.j2", title="Welcome", form=index_form)


        flash("User successfully created!", category="success")
        return redirect(url_for("index"))
    if current_user.is_authenticated:
        return redirect(url_for("stream", username=current_user.username))
    return render_template("index.html.j2", title="Welcome", form=index_form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/stream/<string:username>", methods=["GET", "POST"])
def stream(username: str):
    """Provides the stream page for the application.

    If a form was submitted, it reads the form data and inserts a new post into the database.

    Otherwise, it reads the username from the URL and displays all posts from the user and their friends.
    """
    owner = current_user.is_authenticated and current_user.username == username

    post_form = PostForm()
    get_user = """
        SELECT *
        FROM Users
        WHERE username = ?;
        """
    user = sqlite.query(get_user, username, one=True)

    if post_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to create a post!", category="warning")
            return redirect(url_for("index"))
        if not current_user.username == username:
            flash("You can only create posts on your own stream!", category="warning")
            return redirect(url_for("stream", username=username))
        if post_form.image.data:
            original_name = secure_filename(post_form.image.data.filename)
            name, ext = os.path.splitext(original_name)
            unique_id = uuid.uuid4().hex[:8]  # short random identifier
            filename = f"{username}_{int(time.time())}_{unique_id}{ext}"

            if not allowed_file(filename):
                flash("Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.", category="danger")
                return redirect(url_for("stream", username=username))

            upload_dir = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"]
            upload_dir.mkdir(parents=True, exist_ok=True)

            file_path = upload_dir / filename
            post_form.image.data.save(file_path)

        insert_post = """
            INSERT INTO Posts (u_id, content, image, creation_time)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP);
            """
        sqlite.query(insert_post, user["id"], post_form.content.data, post_form.image.data.filename)

        return redirect(url_for("stream", username=username))

    get_posts = """
         SELECT p.*, u.*, (SELECT COUNT(*) FROM Comments WHERE p_id = p.id) AS cc
         FROM Posts AS p JOIN Users AS u ON u.id = p.u_id
         WHERE p.u_id IN (SELECT u_id FROM Friends WHERE f_id = ?) 
         OR p.u_id IN (SELECT f_id FROM Friends WHERE u_id = ?) 
         OR p.u_id = ?
         ORDER BY p.creation_time DESC;
        """
    posts = sqlite.query(get_posts, user["id"], user["id"], user["id"])
    return render_template("stream.html.j2", title="Stream", username=username, form=post_form, posts=posts)


@app.route("/comments/<string:username>/<int:post_id>", methods=["GET", "POST"])
def comments(username: str, post_id: int):
    """Provides the comments page for the application.

    If a form was submitted, it reads the form data and inserts a new comment into the database.

    Otherwise, it reads the username and post id from the URL and displays all comments for the post.
    """
    owner = current_user.is_authenticated and current_user.username == username

    comments_form = CommentsForm()
    if comments_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to comment!", category="warning")
            return redirect(url_for("index"))
        insert_comment = """
            INSERT INTO Comments (p_id, u_id, comment, creation_time)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP);
            """
        sqlite.query(insert_comment, post_id, current_user.username, comments_form.comment.data)

    get_post = """
        SELECT *
        FROM Posts AS p JOIN Users AS u ON p.u_id = u.id
        WHERE p.id = ?;
        """
    
    post = sqlite.query(get_post, post_id, one=True)

    get_comments = """
        SELECT DISTINCT *
        FROM Comments AS c JOIN Users AS u ON c.u_id = u.id
        WHERE c.p_id = ?
        ORDER BY c.creation_time DESC;
        """

    comments = sqlite.query(get_comments, post_id)
    return render_template(
        "comments.html.j2", title="Comments", owner=owner, username=username, form=comments_form, post=post, comments=comments
    )


@app.route("/friends/<string:username>", methods=["GET", "POST"])
def friends(username: str):
    """Provides the friends page for the application.

    If a form was submitted, it reads the form data and inserts a new friend into the database.

    Otherwise, it reads the username from the URL and displays all friends of the user.
    """
    owner = current_user.is_authenticated and current_user.username == username

    friends_form = FriendsForm()
    get_user = """
        SELECT *
        FROM Users
        WHERE username = ?;
        """
    user = sqlite.query(get_user, username, one=True)

    if friends_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to add friends!", category="warning")
            return redirect(url_for("index"))
        if not current_user.username == username:
            flash("You can only add friends to your own account!", category="warning")
            return redirect(url_for("friends", username=username))
        get_friend = f"""
            SELECT *
            FROM Users
            WHERE username = ?;
            """
        friend = sqlite.query(get_friend, friends_form.username.data, one=True)
        get_friends = """
            SELECT f_id
            FROM Friends
            WHERE u_id = ?;
            """
        friends = sqlite.query(get_friends, user["id"])

        if friend is None:
            flash("User does not exist!", category="warning")
        elif friend["id"] == user["id"]:
            flash("You cannot be friends with yourself!", category="warning")
        elif friend["id"] in [friend["f_id"] for friend in friends]:
            flash("You are already friends with this user!", category="warning")
        else:
            insert_friend = """
                INSERT INTO Friends (u_id, f_id)
                VALUES (?, ?);
                """
            sqlite.query(insert_friend, user["id"], friend["id"])
            flash("Friend successfully added!", category="success")

    get_friends = """
        SELECT *
        FROM Friends AS f JOIN Users as u ON f.f_id = u.id
        WHERE f.u_id = ? AND f.f_id != ?;
        """
    friends = sqlite.query(get_friends, user["id"], user["id"])
    return render_template("friends.html.j2", title="Friends", owner=owner, username=username, friends=friends, form=friends_form)


@app.route("/profile/<string:username>", methods=["GET", "POST"])
def profile(username: str):
    """Provides the profile page for the application.

    If a form was submitted, it reads the form data and updates the user's profile in the database.

    Otherwise, it reads the username from the URL and displays the user's profile.
    """
    owner = current_user.is_authenticated and current_user.username == username

    profile_form = ProfileForm()
    get_user = """
        SELECT *
        FROM Users
        WHERE username = ?;
        """
    user = sqlite.query(get_user, username, one=True)

    if profile_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to update your profile!", category="warning")
            return redirect(url_for("index"))
        if not current_user.username == username:
            flash("You can only update your own profile!", category="warning")
            return redirect(url_for("profile", username=username))
        update_profile = """
            UPDATE Users
            SET education = ?, employment= ?,
                music = ?, movie = ?,
                nationality = ?, birthday = ?
            WHERE username = ?;
            """
        sqlite.query(
            update_profile,
            profile_form.education.data,
            profile_form.employment.data,
            profile_form.music.data,
            profile_form.movie.data,
            profile_form.nationality.data,
            profile_form.birthday.data,
            username,
        )
        return redirect(url_for("profile", username=username))

    return render_template("profile.html.j2", title="Profile", owner=owner,  username=username, user=user, form=profile_form)


@app.route("/uploads/<string:filename>")
def uploads(filename):
    """Provides an endpoint for serving uploaded files."""
    return send_from_directory(Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"], filename)


@app.login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

@app.before_request
#check rate limit function
def _check_rate_limit():
    """
    Very cheap, early check that runs before request processing.
    Returns JSON 429 if the limiter blocks the client.
    """
    # Skip static assets or health checks if needed
    if request.path.startswith("/static") or request.path == "/health":
        return

    # Prefer Flask-Limiter if it exists
    if app.extensions.get("flask_limiter"):
        return

    limiter = app.extensions.get("simple_rate_limiter")
    if limiter is None:
        return

    ip = request.remote_addr or "unknown"
    allowed = limiter.allow(ip)
    if not allowed:
        return jsonify({"error": "Too many requests, try again later."}), 429
    
def setup_request_data():

    """Global session and timeout before every request."""
    sess = session.setdefault("login", {})
    now = datetime.now(timezone.utc)
    current_user = session.get("username")

    # SKIP OPEN ENDPOINTS (important!)
    open_endpoints = ("index", "static", "uploads")
    if request.endpoint in open_endpoints:
        return  # Do not perform login or access checks here

    # Access control (only applies to logged-in routes)
    if request.endpoint and any(name in request.endpoint for name in ("profile", "stream", "friends", "comments")):
        url_username = (request.view_args or {}).get("username")
        current_user = session.get("username")
        if url_username and current_user and current_user != url_username:
            flash("Access denied.", category="danger")
            return redirect(url_for("index"))

    # UUID setup
    if "uuid" not in sess:
        sess["uuid"] = str(uuid.uuid4())
        session["login"] = sess
    else:
        client_uuid = sess["uuid"]
        if client_uuid != sess.get("uuid"):
            session.clear()
            flash("Session invalid. Please log in again.", category="warning")
            return redirect(url_for("index"))

    # Lockout check
    locked_until = sess.get("locked_until")
    if locked_until:
        locked_until_dt = datetime.fromisoformat(locked_until)
        if locked_until_dt > now:
            flash("Too many failed login attempts. Please try again later.", category="warning")
            return redirect(url_for("index"))

    # Timeout tracking
    sess["last_seen"] = now.isoformat()
    session["login"] = sess



def record_session_failure():
    sess = session.setdefault("login", {})
    sess["attempts"] = sess.get("attempts", 0) + 1

    if sess["attempts"] >= Config.SESSION_ATTEMPT_LIMIT:
        tier_index = min(sess["attempts"] - Config.SESSION_ATTEMPT_LIMIT, len(Config.LOCKOUT_TIERS) - 1)
        lock_duration = Config.LOCKOUT_TIERS[tier_index]
        sess["locked_until"] = (datetime.now(timezone.utc) + lock_duration).isoformat()

    session["login"] = sess


def reset_session_counter():
    sess = session.setdefault("login", {})
    sess.pop("attempts", None)
    sess.pop("locked_until", None)
    session["login"] = sess
