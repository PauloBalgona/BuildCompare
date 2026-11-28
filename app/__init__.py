from dotenv import load_dotenv
from flask import Flask, flash, redirect, request, url_for

from .extensions import db, limiter, login_manager, migrate

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "auth.login"

    from app import models  # noqa: F401
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    @app.errorhandler(429)
    def handle_rate_limit(exc):
        app.logger.warning(
            "Rate limit exceeded | ip=%s path=%s",
            request.remote_addr,
            request.path,
        )
        flash("Too many requests. Please wait a moment and try again.", "warning")
        return redirect(request.referrer or url_for("auth.login")), 429

    @app.get("/health")
    def health():
        return {"status": "ok"}, 200

    return app