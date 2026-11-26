from app.extensions import db
from app.models.user import AccountStatus, User, UserRole


def test_landing_and_health(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200


def test_customer_register_and_login(client):
    res_reg = client.post(
        "/auth/register",
        data={
            "role": UserRole.CUSTOMER.value,
            "first_name": "Juan",
            "last_name": "Dela Cruz",
            "email": "juan@example.com",
            "phone": "09171234567",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        follow_redirects=True,
    )
    assert res_reg.status_code == 200

    res_login = client.post(
        "/auth/login",
        data={"email": "juan@example.com", "password": "Password123!"},
        follow_redirects=False,
    )
    assert res_login.status_code == 302


def test_pending_owner_blocked_from_login(app, client):
    with app.app_context():
        owner = User(
            first_name="Maria",
            last_name="Santos",
            email="owner@example.com",
            role=UserRole.OWNER.value,
            account_status=AccountStatus.PENDING.value,
            store_name="Santos Hardware",
            store_location="San Fernando, Pampanga",
        )
        owner.set_password("Password123!")
        db.session.add(owner)
        db.session.commit()

    res = client.post(
        "/auth/login",
        data={"email": "owner@example.com", "password": "Password123!"},
    )
    assert res.status_code == 403