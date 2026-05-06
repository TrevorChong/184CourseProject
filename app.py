from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import hashlib

app = Flask(__name__)
app.config["SECRET_KEY"] = "insecure-demo-key"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


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

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

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

        hashed_input = hashlib.sha256(password.encode()).hexdigest()

        if user and user[2] == hashed_input:
            login_user(User(user[0], user[1], user[2]))
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.")

    return render_template("login.html")


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


