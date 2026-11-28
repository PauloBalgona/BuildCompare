from datetime import datetime, timezone
import json
import os
import re
import smtplib
import socket
import urllib.error
import urllib.request
import uuid
from email.message import EmailMessage
from email.utils import parseaddr
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_user, logout_user
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename

from app.extensions import db, limiter
from app.models.user import AccountStatus, User, UserRole
from app.services.permit_verifier import compute_file_sha256, verify_business_permit

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

ALLOWED_PERMIT_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "webp"}
DEFAULT_MAX_PERMIT_SIZE = 5 * 1024 * 1024  # 5 MB

GMAIL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?@gmail\.com$")
MIN_LENGTH_REGEX = re.compile(r"^.{8,}$")
UPPERCASE_REGEX = re.compile(r"[A-Z]")
LOWERCASE_REGEX = re.compile(r"[a-z]")
DIGIT_REGEX = re.compile(r"\d")
SPECIAL_CHAR_REGEX = re.compile(r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>?/~`]")


def _get_client_ip() -> str:
    if not current_app.config.get("SESSION_COOKIE_SECURE"):
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            first_ip = forwarded_for.split(",")[0].strip()
            if first_ip:
                return first_ip
    return request.remote_addr or "unknown"


def _is_valid_gmail(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    normalized = email.strip().lower()
    if ".." in normalized:
        return False
    return bool(GMAIL_REGEX.match(normalized))


def _validate_strong_password(password: str) -> str | None:
    if not MIN_LENGTH_REGEX.search(password):
        return "Password must be at least 8 characters long."
    if not UPPERCASE_REGEX.search(password):
        return "Password must contain at least one uppercase letter."
    if not LOWERCASE_REGEX.search(password):
        return "Password must contain at least one lowercase letter."
    if not DIGIT_REGEX.search(password):
        return "Password must contain at least one number."
    if not SPECIAL_CHAR_REGEX.search(password):
        return "Password must contain at least one special character (e.g., !@#$%^&*)."
    return None


def _allowed_permit_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_PERMIT_EXTENSIONS


def _matches_file_signature(file_storage, ext: str) -> bool:
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)

    if ext == "pdf":
        return header.startswith(b"%PDF-")
    if ext == "png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in {"jpg", "jpeg"}:
        return header.startswith(b"\xff\xd8\xff")
    if ext == "webp":
        return header.startswith(b"RIFF") and header[8:12] == b"WEBP"
    return False


def _save_business_permit(file_storage) -> tuple[str | None, str | None]:
    """
    Temporary local storage helper para sa local testing.
    Sa production (Render/cloud), ilipat sa object storage (S3 / Supabase Storage / Cloudinary)
    upang hindi mawala ang files sa container restart.
    """
    if not file_storage or not file_storage.filename:
        return None, "Business permit document is required for store owners."

    safe_name = secure_filename(file_storage.filename)
    if not _allowed_permit_file(safe_name):
        return None, "Invalid file type. Allowed formats: PDF, PNG, JPG, JPEG, WEBP."

    max_size = current_app.config.get("MAX_PERMIT_SIZE_BYTES", DEFAULT_MAX_PERMIT_SIZE)
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)

    if size <= 0:
        return None, "Uploaded business permit file is empty."
    if size > max_size:
        return None, "Business permit file must not exceed size limit."

    ext = safe_name.rsplit(".", 1)[1].lower()
    if not _matches_file_signature(file_storage, ext):
        return None, "File content does not match its declared file format."

    unique_name = f"permit_{uuid.uuid4().hex}.{ext}"
    upload_dir = os.path.join(current_app.static_folder, "uploads", "permits")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, unique_name)
    file_storage.save(file_path)

    return url_for("static", filename=f"uploads/permits/{unique_name}"), None


def _role_redirect_url(role: str) -> str:
    role_value = (role or "").lower()
    mapping = {
        UserRole.ADMIN.value: "main.landing",
        UserRole.OWNER.value: "main.landing",
        UserRole.STAFF.value: "main.landing",
        UserRole.DELIVERY.value: "main.landing",
        UserRole.CUSTOMER.value: "main.landing",
    }
    endpoint = mapping.get(role_value, "main.landing")
    try:
        return url_for(endpoint)
    except Exception:
        return url_for("main.landing")


def _generate_reset_token(email: str) -> str:
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return serializer.dumps(email, salt="password-reset-salt")


def _verify_reset_token(token: str, max_age: int = 1800) -> str | None:
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        return serializer.loads(token, salt="password-reset-salt", max_age=max_age)
    except (SignatureExpired, BadSignature):
        return None


def _resolve_smtp_ipv4(host: str, port: int) -> str:
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if addr_info:
            return addr_info[0][4][0]
    except socket.gaierror:
        pass
    return host


def _send_reset_email(recipient_email: str, reset_link: str) -> bool:
    brevo_api_key = os.environ.get("BREVO_API_KEY", "").strip()
    brevo_timeout = current_app.config.get("BREVO_TIMEOUT_SECONDS", 8)
    smtp_timeout = current_app.config.get("SMTP_TIMEOUT_SECONDS", 10)

    raw_sender = (
        os.environ.get("MAIL_DEFAULT_SENDER")
        or os.environ.get("MAIL_USERNAME")
        or ""
    ).strip()
    sender_name, sender_email = parseaddr(raw_sender)
    sender_name = sender_name or "BuildCompare"
    sender_email = sender_email or raw_sender

    text_body = (
        f"Hi,\n\n"
        f"We received a request to reset your BuildCompare password.\n"
        f"Click the link below to set a new password (valid for 30 minutes):\n"
        f"{reset_link}\n\n"
        f"If you did not request this, you can safely ignore this email.\n\n"
        f"— BuildCompare"
    )

    html_body = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #111827; max-width: 520px;">
      <h2 style="margin-bottom: 8px;">Reset your BuildCompare password</h2>
      <p style="color: #4b5563; margin-top: 0;">
        We received a request to reset the password for your account. Click the button below to choose a new password:
      </p>
      <p style="margin: 24px 0;">
        <a href="{reset_link}"
           style="display: inline-block; padding: 12px 20px; background-color: #111827; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600;">
          Reset Password
        </a>
      </p>
      <p style="font-size: 13px; color: #6b7280;">
        This link will expire in 30 minutes. If you didn't request a password reset, you can ignore this message.
      </p>
      <p style="font-size: 12px; color: #9ca3af; word-break: break-all;">
        Or copy and paste this URL into your browser:<br>
        {reset_link}
      </p>
    </div>
    """

    if brevo_api_key and sender_email:
        payload = json.dumps(
            {
                "sender": {"name": sender_name, "email": sender_email},
                "to": [{"email": recipient_email}],
                "subject": "Reset Your BuildCompare Password",
                "htmlContent": html_body,
                "textContent": text_body,
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email",
            data=payload,
            headers={
                "accept": "application/json",
                "api-key": brevo_api_key,
                "content-type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=brevo_timeout) as response:
                if 200 <= response.status < 300:
                    return True
                current_app.logger.error(
                    "Brevo API unexpected status %s for %s",
                    response.status,
                    recipient_email,
                )
                return False
        except urllib.error.HTTPError as exc:
            error_detail = exc.read().decode("utf-8", errors="ignore")
            current_app.logger.error(
                "Brevo API HTTP error (%s) for %s: %s",
                exc.code,
                recipient_email,
                error_detail,
            )
            return False
        except Exception as exc:
            current_app.logger.error(
                "Brevo API request failed for %s: %s",
                recipient_email,
                exc,
            )
            return False

    smtp_server = os.environ.get("MAIL_SERVER", "smtp.gmail.com").strip()
    smtp_port = int(os.environ.get("MAIL_PORT", "587"))
    use_tls = os.environ.get("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes", "on")
    use_ssl = os.environ.get("MAIL_USE_SSL", "false").lower() in ("1", "true", "yes", "on")
    username = os.environ.get("MAIL_USERNAME", "").strip()
    password = os.environ.get("MAIL_PASSWORD", "").strip()

    if not username or not password:
        current_app.logger.warning(
            "Email credentials not configured. Reset link for %s: %s",
            recipient_email,
            reset_link,
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = "Reset Your BuildCompare Password"
    msg["From"] = raw_sender or username
    msg["To"] = recipient_email
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    connect_host = _resolve_smtp_ipv4(smtp_server, smtp_port)

    try:
        if smtp_port == 465 or use_ssl:
            with smtplib.SMTP_SSL(connect_host, smtp_port, timeout=smtp_timeout) as server:
                server.ehlo()
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(connect_host, smtp_port, timeout=smtp_timeout) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                server.login(username, password)
                server.send_message(msg)
        return True
    except Exception as exc:
        current_app.logger.error("SMTP send failed for %s: %s", recipient_email, exc)
        return False


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["AUTH_LOGIN_LIMIT"], key_func=_get_client_ip)
def login():
    if current_user.is_authenticated:
        return redirect(_role_redirect_url(current_user.role))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        client_ip = _get_client_ip()

        if not email or not password:
            current_app.logger.warning("Failed login (missing credentials) | ip=%s", client_ip)
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html"), 401

        user = db.session.scalar(db.select(User).where(User.email == email))
        if not user or not user.check_password(password) or not user.is_active:
            current_app.logger.warning("Failed login attempt | ip=%s email=%s", client_ip, email)
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html"), 401

        if user.account_status != AccountStatus.APPROVED.value:
            current_app.logger.info("Unapproved login attempt | ip=%s user_id=%s", client_ip, user.id)
            flash(
                "Your account is pending admin verification. Please wait for account approval before signing in.",
                "warning",
            )
            return render_template("auth/login.html"), 403

        login_user(user, remember=False)
        current_app.logger.info("Successful login | ip=%s user_id=%s role=%s", client_ip, user.id, user.role)
        flash(f"Welcome back, {user.first_name}!", "success")
        return redirect(_role_redirect_url(user.role))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["AUTH_REGISTER_LIMIT"], key_func=_get_client_ip)
def register():
    if current_user.is_authenticated:
        return redirect(_role_redirect_url(current_user.role))

    if request.method == "POST":
        selected_role = request.form.get("role", UserRole.CUSTOMER.value).strip().lower()
        if selected_role not in {UserRole.CUSTOMER.value, UserRole.OWNER.value}:
            selected_role = UserRole.CUSTOMER.value

        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([first_name, last_name, email, password, confirm_password]):
            flash("Please fill in all required fields.", "danger")
            return render_template("auth/register.html", selected_role=selected_role), 400

        if not _is_valid_gmail(email):
            flash("Please enter a valid @gmail.com email address.", "danger")
            return render_template("auth/register.html", selected_role=selected_role), 400

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html", selected_role=selected_role), 400

        password_error = _validate_strong_password(password)
        if password_error:
            flash(password_error, "danger")
            return render_template("auth/register.html", selected_role=selected_role), 400

        existing = db.session.scalar(db.select(User).where(User.email == email))
        if existing:
            flash("Unable to create account with that email.", "danger")
            return render_template("auth/register.html", selected_role=selected_role), 409

        store_name = None
        store_location = None
        permit_url = None
        permit_hash = None
        verification_method = None
        verification_notes = None
        verified_at = None
        status = AccountStatus.APPROVED.value

        if selected_role == UserRole.OWNER.value:
            store_name = request.form.get("store_name", "").strip()
            store_location = request.form.get("store_location", "").strip()
            permit_file = request.files.get("business_permit")

            if not store_name or not store_location:
                flash("Store name and location are required for hardware owners.", "danger")
                return render_template("auth/register.html", selected_role=selected_role), 400

            permit_url, err = _save_business_permit(permit_file)
            if err:
                flash(err, "danger")
                return render_template("auth/register.html", selected_role=selected_role), 400

            permit_file.stream.seek(0)
            permit_bytes = permit_file.stream.read()
            permit_file.stream.seek(0)

            candidate_hash = compute_file_sha256(permit_bytes)
            duplicate_user = db.session.scalar(
                db.select(User).where(User.permit_file_hash == candidate_hash)
            )

            verification = verify_business_permit(
                file_bytes=permit_bytes,
                store_name=store_name,
                store_location=store_location,
                duplicate_exists=bool(duplicate_user),
            )

            permit_hash = verification.file_hash
            verification_method = verification.method
            verification_notes = verification.notes

            if verification.auto_approve:
                status = AccountStatus.APPROVED.value
                verified_at = datetime.now(timezone.utc)
            else:
                status = AccountStatus.PENDING.value

        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone or None,
            role=selected_role,
            account_status=status,
            store_name=store_name,
            store_location=store_location,
            business_permit_url=permit_url,
            permit_file_hash=permit_hash,
            verification_method=verification_method,
            verification_notes=verification_notes,
            verified_at=verified_at,
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        if selected_role == UserRole.OWNER.value:
            if status == AccountStatus.APPROVED.value:
                flash(
                    "Owner account verified and approved automatically! You can now sign in.",
                    "success",
                )
            else:
                flash(
                    "Owner account submitted! Your business permit has been queued for admin review before login access is granted.",
                    "info",
                )
        else:
            flash("Account created successfully! You can now sign in.", "success")

        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", selected_role=UserRole.CUSTOMER.value)


@auth_bp.route("/internal-admin-setup", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["AUTH_ADMIN_SETUP_LIMIT"], key_func=_get_client_ip)
def register_admin():
    if request.method == "POST":
        setup_key = request.form.get("setup_key", "").strip()
        expected_key = os.environ.get("ADMIN_SETUP_KEY", "")
        client_ip = _get_client_ip()

        if not expected_key or setup_key != expected_key:
            current_app.logger.warning("Unauthorized admin setup attempt | ip=%s", client_ip)
            flash("Invalid or unauthorized setup key.", "danger")
            return render_template("auth/register_admin.html"), 403

        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([first_name, last_name, email, password, confirm_password]):
            flash("Please fill in all required fields.", "danger")
            return render_template("auth/register_admin.html"), 400

        if not _is_valid_gmail(email):
            flash("Admin email must be a valid @gmail.com address.", "danger")
            return render_template("auth/register_admin.html"), 400

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register_admin.html"), 400

        password_error = _validate_strong_password(password)
        if password_error:
            flash(password_error, "danger")
            return render_template("auth/register_admin.html"), 400

        existing = db.session.scalar(db.select(User).where(User.email == email))
        if existing:
            flash("Unable to create account with that email.", "danger")
            return render_template("auth/register_admin.html"), 409

        admin_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone or None,
            role=UserRole.ADMIN.value,
            account_status=AccountStatus.APPROVED.value,
        )
        admin_user.set_password(password)

        db.session.add(admin_user)
        db.session.commit()

        current_app.logger.warning("Admin account created | ip=%s email=%s", client_ip, email)
        flash("Admin account created successfully! You can now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register_admin.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["AUTH_FORGOT_LIMIT"], key_func=_get_client_ip)
def forgot_password():
    if current_user.is_authenticated:
        return redirect(_role_redirect_url(current_user.role))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email or not _is_valid_gmail(email):
            flash("Please enter a valid @gmail.com email address.", "danger")
            return render_template("auth/forgot_password.html"), 400

        user = db.session.scalar(db.select(User).where(User.email == email))

        flash(
            "If an account exists for that email, password reset instructions have been generated.",
            "info",
        )

        if user and user.is_active:
            token = _generate_reset_token(user.email)
            reset_link = url_for("auth.reset_password", token=token, _external=True)
            _send_reset_email(user.email, reset_link)

        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["AUTH_RESET_LIMIT"], key_func=_get_client_ip)
def reset_password(token: str):
    email = _verify_reset_token(token)
    if not email:
        flash("That password reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        password_error = _validate_strong_password(password)
        if password_error:
            flash(password_error, "danger")
            return render_template("auth/reset_password.html", token=token), 400

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/reset_password.html", token=token), 400

        user = db.session.scalar(db.select(User).where(User.email == email))
        if not user:
            flash("Account not found.", "danger")
            return redirect(url_for("auth.login"))

        user.set_password(password)
        db.session.commit()

        flash("Your password has been updated. You can now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", token=token)


@auth_bp.get("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.landing"))