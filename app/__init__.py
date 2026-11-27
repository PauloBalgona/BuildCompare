from flask import Flask
from .extensions import db, login_manager, migrate
from dotenv import load_dotenv

load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    from app import models  # noqa: F401
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    @app.get("/health")
    def health():
        return {"status": "ok"}, 200

    return app