from flask import Flask
from db import close_db, init_db

# blueprints
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.agent import agent_bp
from routes.stream import stream_bp
from routes.main import main_bp


def create_app():
    app = Flask(__name__)

    # ==============================
    # 🔐 CONFIG
    # ==============================
    app.secret_key = "supersecret"  # depois trocar por ENV

    # ==============================
    # 📦 REGISTRAR BLUEPRINTS
    # ==============================
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(agent_bp)
    app.register_blueprint(stream_bp)
    app.register_blueprint(main_bp)

    # ==============================
    # 🔌 FECHAR DB AUTOMATICAMENTE
    # ==============================
    app.teardown_appcontext(close_db)

    return app


# ==============================
# 🚀 INICIALIZAÇÃO
# ==============================
app = create_app()

# criar tabelas (uma vez)
with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)