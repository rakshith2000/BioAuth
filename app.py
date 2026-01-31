import uuid
import json, base64
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from passlib.hash import bcrypt
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response
)

def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

# --------------------------------------------------
# APP CONFIG
# --------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = "CHANGE_ME"
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://admin:4yNDydMdQ1uIPGG4kI4GrAZYh7fSpqSg@dpg-d5uprkffte5s73c7oa1g-a.singapore-postgres.render.com/bioauth"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"

RP_ID = "localhost"
ORIGIN = "http://localhost:5000"

# --------------------------------------------------
# MODELS
# --------------------------------------------------

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.Text)

    webauthn_credential_id = db.Column(db.LargeBinary)
    webauthn_public_key = db.Column(db.LargeBinary)
    webauthn_sign_count = db.Column(db.Integer, default=0)

class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.UUID(as_uuid=True), db.ForeignKey("users.id"))
    content = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# --------------------------------------------------
# BASIC ROUTES
# --------------------------------------------------

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))

# --------------------------------------------------
# REGISTER (PASSWORD)
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for("register_page"))

        user = User(
            username=username,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please login.")
        return redirect(url_for("login_page"))

    return render_template("register.html")

# --------------------------------------------------
# LOGIN (PASSWORD)
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print(username, password)

        user = User.query.filter_by(username=username).first()

        if not user or not user.password_hash:
            flash("Invalid username or password")
            return redirect(url_for("login_page"))

        if not check_password_hash(user.password_hash, password):
            flash("Invalid username or password")
            return redirect(url_for("login_page"))

        login_user(user)
        return redirect(url_for("dashboard"))

    return render_template("login.html")

# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login_page"))

# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

# --------------------------------------------------
# WEB AUTHN – REGISTER
# --------------------------------------------------

@app.route("/webauthn/register/options")
@login_required
def webauthn_register_options():
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="Flask Hybrid Auth",
        user_id=current_user.id.bytes,
        user_name=current_user.username,
    )

    session["webauthn_reg_challenge"] = options.challenge
    response = {
        "challenge": b64encode(options.challenge),
        "rp": {
            "name": options.rp.name,
            "id": options.rp.id,
        },
        "user": {
            "id": b64encode(options.user.id),
            "name": options.user.name,
            "displayName": options.user.display_name,
        },
        "pubKeyCredParams": [
            {
                "type": p.type,
                "alg": p.alg
            } for p in options.pub_key_cred_params
        ],
        "timeout": options.timeout,
        "attestation": options.attestation,
    }
    return jsonify(response)

@app.route("/webauthn/register/verify", methods=["POST"])
@login_required
def webauthn_register_verify():
    credential = verify_registration_response(
        credential=request.json,
        expected_challenge=session.get("webauthn_reg_challenge"),
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )

    current_user.webauthn_credential_id = credential.credential_id
    current_user.webauthn_public_key = credential.credential_public_key
    current_user.webauthn_sign_count = credential.sign_count

    db.session.commit()
    return {"status": "biometric_registered"}

# --------------------------------------------------
# WEB AUTHN – LOGIN
# --------------------------------------------------

@app.route("/webauthn/login/options", methods=["POST"])
def webauthn_login_options():
    username = request.json.get("username")
    user = User.query.filter_by(username=username).first()

    if not user or not user.webauthn_credential_id:
        return jsonify({"error": "Biometric not registered"}), 400

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[{
            "id": user.webauthn_credential_id,
            "type": "public-key"
        }]
    )

    session["webauthn_auth_challenge"] = options.challenge
    session["webauthn_auth_user"] = str(user.id)

    response = {
        "challenge": b64encode(options.challenge),
        "timeout": options.timeout,
        "rpId": options.rp_id,
        "allowCredentials": [
            {
                "id": b64encode(cred['id']),
                "type": cred['type']
            } for cred in options.allow_credentials
        ],
        "userVerification": "preferred"
        }

    return jsonify(response)

@app.route("/webauthn/login/verify", methods=["POST"])
def webauthn_login_verify():
    user = User.query.get(session.get("webauthn_auth_user"))

    verification = verify_authentication_response(
        credential=request.json,
        expected_challenge=session.get("webauthn_auth_challenge"),
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=user.webauthn_public_key,
        credential_current_sign_count=user.webauthn_sign_count,
    )

    user.webauthn_sign_count = verification.new_sign_count
    db.session.commit()

    login_user(user)
    return {"status": "logged_in"}

# --------------------------------------------------
# CRUD – NOTES
# --------------------------------------------------

@app.route("/notes", methods=["GET"])
@login_required
def list_notes():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return jsonify([n.content for n in notes])

@app.route("/notes", methods=["POST"])
@login_required
def create_note():
    content = request.json.get("content")
    if not content:
        return {"error": "Empty note"}, 400

    note = Note(user_id=current_user.id, content=content)
    db.session.add(note)
    db.session.commit()
    return {"status": "created"}

# --------------------------------------------------
# INIT
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)