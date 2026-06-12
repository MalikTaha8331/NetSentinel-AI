from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'netsentinel-secret-key-2025'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'database', 'netsentinel.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    from app.scanner.models import ScanResult
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access NetSentinel.'

    from app.auth.routes import auth
    app.register_blueprint(auth)

    from app.main.routes import main
    app.register_blueprint(main)

    with app.app_context():
        os.makedirs(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'database'), exist_ok=True)
        db.create_all()

    return app