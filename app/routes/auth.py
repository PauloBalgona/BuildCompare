import os
import uuid
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
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


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.landing"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.session.scalar(db.select(User).where(User.email == email))
        if not user or not user.check_password(password) or not user.is_active:
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html"), 401

        if user.account_status != AccountStatus.APPROVED.value:
            flash(
                "Your account is pending admin verification. Please wait for your business permit approval.",
                "warning",
            )
            return render_template("auth/login.html"), 403

        login_user(user)
        flash(f"Welcome back, {user.first_name}!", "success")
        return redirect(url_for("main.landing"))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.landing"))

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


@auth_bp.get("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.landing"))