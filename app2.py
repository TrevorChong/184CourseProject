from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import sqlite3
import random
import time
import os

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["REMEMBER_COOKIE_DURATION"] = 0

## "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"

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)


def get_db():
    return sqlite3.connect("users.db")


def create_table():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    db.commit()
    db.close()


class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()

    if user:
        return User(user[0], user[1], user[2])
    return None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, hashed_password)
            )
            db.commit()
            db.close()

            flash("Account created. Please log in.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Email already exists.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        db.close()

        if user and bcrypt.check_password_hash(user[2], password):
            otp = str(random.randint(100000, 999999))

            session["pending_user_id"] = user[0]
            session["otp"] = otp
            session["otp_time"] = time.time()

            print("================================")
            print(f"OTP for {email}: {otp}")
            print("================================")

            return redirect(url_for("verify_otp"))

        flash("Invalid email or password.")

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        entered_otp = request.form["otp"]
        saved_otp = session.get("otp")
        otp_time = session.get("otp_time")

        if time.time() - otp_time > 120:
            flash("OTP expired. Please log in again.")
            session.clear()
            return redirect(url_for("login"))

        if entered_otp == saved_otp:
            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE id = ?",
                (session["pending_user_id"],)
            ).fetchone()
            db.close()

            login_user(User(user[0], user[1], user[2]))

            session.pop("pending_user_id", None)
            session.pop("otp", None)
            session.pop("otp_time", None)

            return redirect(url_for("dashboard"))

        flash("Invalid OTP.")

    return render_template("verify_otp.html")


@app.route("/auth/google")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    token = google.authorize_access_token()
    user_info = token.get("userinfo")

    if not user_info:
        user_info = google.get("https://openidconnect.googleapis.com/v1/userinfo").json()

    email = user_info["email"]

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        db.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, "GOOGLE_OAUTH_USER")
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    db.close()

    login_user(User(user[0], user[1], user[2]))
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", email=current_user.email)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    create_table()
    app.run(debug=True)

