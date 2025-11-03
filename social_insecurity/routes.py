from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import current_app as app
from flask import flash, redirect, render_template, send_from_directory, session, url_for, request

from social_insecurity import sqlite
from social_insecurity.config import Config
from social_insecurity.forms import CommentsForm, FriendsForm, IndexForm, PostForm, ProfileForm
import uuid

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

    if login_form.is_submitted() and login_form.submit.data:
        get_user = f"""
            SELECT *
            FROM Users
            WHERE username = '{login_form.username.data}';
            """
        user = sqlite.query(get_user, one=True)
        if user is None:
            flash("Invalid username or password!", category="warning")
            record_session_failure()
        elif user["password"] != login_form.password.data:
            flash("Invalid username or password!", category="warning")
            record_session_failure()
        else:
            reset_session_counter()
            session["username"] = login_form.username.data
            return redirect(url_for("stream", username=login_form.username.data))

    elif register_form.is_submitted() and register_form.submit.data:
        insert_user = f"""
            INSERT INTO Users (username, first_name, last_name, password)
            VALUES ('{register_form.username.data}', '{register_form.first_name.data}', '{register_form.last_name.data}', '{register_form.password.data}');
            """
        sqlite.query(insert_user)
        flash("User successfully created!", category="success")
        return redirect(url_for("index"))

    # Før loginforsøk – blokker hvis låst
    sess = session.get("login", {})
    locked_until = sess.get("locked_until")
    if locked_until:
        locked_until_dt = datetime.fromisoformat(locked_until)
        if locked_until_dt > datetime.now(timezone.utc):
            flash("Too many failed login attempts. Please try again later.", category="warning")
            return render_template("index.html.j2", title="Welcome", form=index_form)



@app.route("/stream/<string:username>", methods=["GET", "POST"])
def stream(username: str):
    """Provides the stream page for the application.

    If a form was submitted, it reads the form data and inserts a new post into the database.

    Otherwise, it reads the username from the URL and displays all posts from the user and their friends.
    """
    post_form = PostForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if post_form.is_submitted():
        if post_form.image.data:
            path = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"] / post_form.image.data.filename
            post_form.image.data.save(path)

        insert_post = f"""
            INSERT INTO Posts (u_id, content, image, creation_time)
            VALUES ({user["id"]}, '{post_form.content.data}', '{post_form.image.data.filename}', CURRENT_TIMESTAMP);
            """
        sqlite.query(insert_post)
        return redirect(url_for("stream", username=username))

    get_posts = f"""
         SELECT p.*, u.*, (SELECT COUNT(*) FROM Comments WHERE p_id = p.id) AS cc
         FROM Posts AS p JOIN Users AS u ON u.id = p.u_id
         WHERE p.u_id IN (SELECT u_id FROM Friends WHERE f_id = {user["id"]}) OR p.u_id IN (SELECT f_id FROM Friends WHERE u_id = {user["id"]}) OR p.u_id = {user["id"]}
         ORDER BY p.creation_time DESC;
        """
    posts = sqlite.query(get_posts)
    return render_template("stream.html.j2", title="Stream", username=username, form=post_form, posts=posts)


@app.route("/comments/<string:username>/<int:post_id>", methods=["GET", "POST"])
def comments(username: str, post_id: int):
    """Provides the comments page for the application.

    If a form was submitted, it reads the form data and inserts a new comment into the database.

    Otherwise, it reads the username and post id from the URL and displays all comments for the post.
    """
    comments_form = CommentsForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if comments_form.is_submitted():
        insert_comment = f"""
            INSERT INTO Comments (p_id, u_id, comment, creation_time)
            VALUES ({post_id}, {user["id"]}, '{comments_form.comment.data}', CURRENT_TIMESTAMP);
            """
        sqlite.query(insert_comment)

    get_post = f"""
        SELECT *
        FROM Posts AS p JOIN Users AS u ON p.u_id = u.id
        WHERE p.id = {post_id};
        """
    get_comments = f"""
        SELECT DISTINCT *
        FROM Comments AS c JOIN Users AS u ON c.u_id = u.id
        WHERE c.p_id={post_id}
        ORDER BY c.creation_time DESC;
        """
    post = sqlite.query(get_post, one=True)
    comments = sqlite.query(get_comments)
    return render_template(
        "comments.html.j2", title="Comments", username=username, form=comments_form, post=post, comments=comments
    )


@app.route("/friends/<string:username>", methods=["GET", "POST"])
def friends(username: str):
    """Provides the friends page for the application.

    If a form was submitted, it reads the form data and inserts a new friend into the database.

    Otherwise, it reads the username from the URL and displays all friends of the user.
    """
    friends_form = FriendsForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if friends_form.is_submitted():
        get_friend = f"""
            SELECT *
            FROM Users
            WHERE username = '{friends_form.username.data}';
            """
        friend = sqlite.query(get_friend, one=True)
        get_friends = f"""
            SELECT f_id
            FROM Friends
            WHERE u_id = {user["id"]};
            """
        friends = sqlite.query(get_friends)

        if friend is None:
            flash("User does not exist!", category="warning")
        elif friend["id"] == user["id"]:
            flash("You cannot be friends with yourself!", category="warning")
        elif friend["id"] in [friend["f_id"] for friend in friends]:
            flash("You are already friends with this user!", category="warning")
        else:
            insert_friend = f"""
                INSERT INTO Friends (u_id, f_id)
                VALUES ({user["id"]}, {friend["id"]});
                """
            sqlite.query(insert_friend)
            flash("Friend successfully added!", category="success")

    get_friends = f"""
        SELECT *
        FROM Friends AS f JOIN Users as u ON f.f_id = u.id
        WHERE f.u_id = {user["id"]} AND f.f_id != {user["id"]};
        """
    friends = sqlite.query(get_friends)
    return render_template("friends.html.j2", title="Friends", username=username, friends=friends, form=friends_form)


@app.route("/profile/<string:username>", methods=["GET", "POST"])
def profile(username: str):
    """Provides the profile page for the application.

    If a form was submitted, it reads the form data and updates the user's profile in the database.

    Otherwise, it reads the username from the URL and displays the user's profile.
    """
    profile_form = ProfileForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if profile_form.is_submitted():
        update_profile = f"""
            UPDATE Users
            SET education='{profile_form.education.data}', employment='{profile_form.employment.data}',
                music='{profile_form.music.data}', movie='{profile_form.movie.data}',
                nationality='{profile_form.nationality.data}', birthday='{profile_form.birthday.data}'
            WHERE username='{username}';
            """
        sqlite.query(update_profile)
        return redirect(url_for("profile", username=username))

    return render_template("profile.html.j2", title="Profile", username=username, user=user, form=profile_form)


@app.route("/uploads/<string:filename>")
def uploads(filename):
    """Provides an endpoint for serving uploaded files."""
    return send_from_directory(Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"], filename)


@app.before_request
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

