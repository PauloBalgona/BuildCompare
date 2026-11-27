import json
import os
import smtplib
import socket
import urllib.error
import urllib.request
import uuid
from email.message import EmailMessage
from email.utils import parseaddr
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from app.extensions import db
from app.models.user import AccountStatus, User, UserRole

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

ALLOWED_PERMIT_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "webp"}
MAX_PERMIT_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


def _allowed_permit_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_PERMIT_EXTENSIONS


def _save_business_permit(file_storage) -> tuple[str | None, str | None]:
    """
    Temporary local storage helper para ma-test agad ang upload flow.
    Kapag nag-deploy sa cloud/Render, ilipat ito sa Supabase Storage / S3
    para hindi mawala ang file sa container restart.
    """
    if not file_storage or not file_storage.filename:
        return None, "Business permit document is required for store owners."

    if not _allowed_permit_file(file_storage.filename):
        return None, "Invalid file type. Allowed formats: PDF, PNG, JPG, JPEG, WEBP."

    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > MAX_PERMIT_SIZE_BYTES:
        return None, "Business permit file must not exceed 5 MB."

    ext = secure_filename(file_storage.filename).rsplit(".", 1)[1].lower()
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

    # 1. Gamitin ang Brevo HTTPS API (Port 443 - hindi naka-block sa Render)
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
            with urllib.request.urlopen(req, timeout=15) as response:
                if 200 <= response.status < 300:
                    return True
                current_app.logger.error(
                    "Brevo API returned unexpected status %s for %s",
                    response.status,
                    recipient_email,
                )
                return False
        except urllib.error.HTTPError as exc:
            error_detail = exc.read().decode("utf-8", errors="ignore")
            current_app.logger.error(
                "Brevo API HTTP error (%s) sending to %s: %s",
                exc.code,
                recipient_email,
                error_detail,
            )
            return False
        except Exception as exc:
            current_app.logger.error(
                "Failed to send reset email via Brevo API to %s: %s",
                recipient_email,
                exc,
            )
            return False

    # 2. Fallback sa SMTP para sa local development
    smtp_server = os.environ.get("MAIL_SERVER", "smtp.gmail.com").strip()
    smtp_port = int(os.environ.get("MAIL_PORT", "587"))
    use_tls = os.environ.get("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes", "on")
    use_ssl = os.environ.get("MAIL_USE_SSL", "false").lower() in ("1", "true", "yes", "on")
    username = os.environ.get("MAIL_USERNAME", "").strip()
    password = os.environ.get("MAIL_PASSWORD", "").strip()

    if not username or not password:
        current_app.logger.warning(
            "Email credentials are not configured. Reset link for %s: %s",
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
            with smtplib.SMTP_SSL(connect_host, smtp_port, timeout=20) as server:
                server.ehlo()
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(connect_host, smtp_port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                server.login(username, password)
                server.send_message(msg)
        return True
    except Exception as exc:
        current_app.logger.error("Failed to send reset email to %s: %s", recipient_email, exc)
        return False


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(_role_redirect_url(current_user.role))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.session.scalar(db.select(User).where(User.email == email))
        if not user or not user.check_password(password) or not user.is_active:
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html"), 401

        if user.account_status != AccountStatus.APPROVED.value:
            flash(
                "Your account is pending admin verification. Please wait for account approval before signing in.",
                "warning",
            )
            return render_template("auth/login.html"), 403

        login_user(user)
        flash(f"Welcome back, {user.first_name}!", "success")
        return redirect(_role_redirect_url(user.role))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
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

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html", selected_role=selected_role), 400

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("auth/register.html", selected_role=selected_role), 400

        existing = db.session.scalar(db.select(User).where(User.email == email))
        if existing:
            flash("Unable to create account with that email.", "danger")
            return render_template("auth/register.html", selected_role=selected_role), 409

        store_name = None
        store_location = None
        permit_url = None
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
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        if selected_role == UserRole.OWNER.value:
            flash(
                "Owner account submitted! Your business permit is under admin review before login access is granted.",
                "info",
            )
        else:
            flash("Account created successfully! You can now sign in.", "success")

        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", selected_role=UserRole.CUSTOMER.value)


@auth_bp.route("/internal-admin-setup", methods=["GET", "POST"])
def register_admin():
    if request.method == "POST":
        setup_key = request.form.get("setup_key", "").strip()
        expected_key = os.environ.get("ADMIN_SETUP_KEY", "")

        if not expected_key or setup_key != expected_key:
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

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register_admin.html"), 400

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
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

        flash("Admin account created successfully! You can now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register_admin.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(_role_redirect_url(current_user.role))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Please enter your email address.", "danger")
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
def reset_password(token: str):
    email = _verify_reset_token(token)
    if not email:
        flash("That password reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
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