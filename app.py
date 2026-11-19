
import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
DATABASE = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "gelistirme-anahtari")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

def db_connect():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS listings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                phone TEXT NOT NULL,
                image TEXT NOT NULL
            )
        """)

        admin_username = os.environ.get("ADMIN_USERNAME")
        admin_password = os.environ.get("ADMIN_PASSWORD")

        if admin_username and admin_password:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (admin_username,)
            ).fetchone()

            if existing is None:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (admin_username, generate_password_hash(admin_password))
                )

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    with db_connect() as conn:
        listings = conn.execute("SELECT * FROM listings ORDER BY id DESC").fetchall()
    return render_template("index.html", listings=listings)

@app.route("/ilan/<int:listing_id>")
def detail(listing_id):
    with db_connect() as conn:
        listing = conn.execute("SELECT * FROM listings WHERE id = ?", (listing_id,)).fetchone()
    if listing is None:
        abort(404)
    return render_template("detail.html", listing=listing)

@app.route("/giris", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        with db_connect() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["admin_id"] = user["id"]
            return redirect(url_for("admin"))
        flash("Kullanıcı adı veya şifre hatalı.")
    return render_template("login.html")

@app.route("/yonetim")
@admin_required
def admin():
    with db_connect() as conn:
        listings = conn.execute("SELECT * FROM listings ORDER BY id DESC").fetchall()
    return render_template("admin.html", listings=listings)

@app.route("/ilan-ekle", methods=["POST"])
@admin_required
def add_listing():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    price = request.form.get("price", "").strip()
    phone = request.form.get("phone", "").strip()
    photo = request.files.get("photo")

    if not all([title, description, price, phone, photo]):
        flash("Lütfen bütün alanları doldur.")
        return redirect(url_for("admin"))

    if not allowed_file(photo.filename):
        flash("Sadece JPG, PNG ve WEBP fotoğrafları yükleyebilirsin.")
        return redirect(url_for("admin"))

    filename = secure_filename(photo.filename)
    if not filename:
        flash("Geçerli bir fotoğraf adı gerekli.")
        return redirect(url_for("admin"))

    filename = os.urandom(8).hex() + "_" + filename
    photo.save(os.path.join(UPLOAD_FOLDER, filename))

    with db_connect() as conn:
        conn.execute(
            "INSERT INTO listings (title, description, price, phone, image) VALUES (?, ?, ?, ?, ?)",
            (title, description, price, phone, filename)
        )

    flash("İlan başarıyla yayınlandı.")
    return redirect(url_for("admin"))

@app.route("/ilan-sil/<int:listing_id>", methods=["POST"])
@admin_required
def delete_listing(listing_id):
    with db_connect() as conn:
        listing = conn.execute("SELECT * FROM listings WHERE id = ?", (listing_id,)).fetchone()
        if listing:
            conn.execute("DELETE FROM listings WHERE id = ?", (listing_id,))
            image_path = os.path.join(UPLOAD_FOLDER, listing["image"])
            if os.path.isfile(image_path):
                os.remove(image_path)
    flash("İlan silindi.")
    return redirect(url_for("admin"))

@app.route("/cikis", methods=["POST"])
@admin_required
def logout():
    session.clear()
    return redirect(url_for("index"))

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
