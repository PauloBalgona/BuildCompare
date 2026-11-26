from datetime import datetime, timezone
from enum import Enum
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from app.extensions import db, login_manager


class UserRole(str, Enum):
    CUSTOMER = "customer"
    OWNER = "owner"
    STAFF = "staff"
    DELIVERY = "delivery"
    ADMIN = "admin"


class AccountStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(30), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(32), default=UserRole.CUSTOMER.value, nullable=False, index=True)
    account_status = db.Column(
        db.String(32),
        default=AccountStatus.APPROVED.value,
        nullable=False,
        index=True,
    )

    # Owner store verification fields (ginagamit kapag role == "owner")
    store_name = db.Column(db.String(180), nullable=True)
    store_location = db.Column(db.String(220), nullable=True)
    business_permit_url = db.Column(db.String(500), nullable=True)

    # Para sa staff o delivery na nasa ilalim ng owner
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    team_members = db.relationship(
        "User",
        backref=db.backref("owner", remote_side=[id]),
        lazy="dynamic",
    )

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))