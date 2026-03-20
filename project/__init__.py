import os
import logging
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore
from werkzeug.security import generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

from .models import User, Role
user_datastore = SQLAlchemyUserDatastore(db, User, Role)

LOG_FILENAME = 'logs/app.log'
os.makedirs('logs', exist_ok=True)

logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def create_app():
    app = Flask(__name__)

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:1234@localhost/flasksecurity'
    app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha256'
    app.config['SECURITY_PASSWORD_SALT'] = 'thisissecretsalt'

    security = Security(app, user_datastore)
    db.init_app(app)

    with app.app_context():
        @app.before_request
        def create_all():
            app.before_request_funcs[None].remove(create_all)
            db.create_all()

            user_datastore.find_or_create_role(name='admin', description='Administrator')
            user_datastore.find_or_create_role(name='end-user', description='End user')

            encrypted_password = generate_password_hash('password', method='pbkdf2:sha256')

            if not user_datastore.find_user(email='juan@example.com'):
                user_datastore.create_user(name='Juan', email='juan@example.com', password=encrypted_password)
            if not user_datastore.find_user(email='admin@example.com'):
                user_datastore.create_user(name='Ismael', email='admin@example.com', password=encrypted_password)

            db.session.commit()

            user_datastore.add_role_to_user(user_datastore.find_user(email='juan@example.com'), 'end-user')
            user_datastore.add_role_to_user(user_datastore.find_user(email='admin@example.com'), 'admin')
            db.session.commit()

        logging.info('EVENTO: INICIO_APP | La aplicacion Flask ha iniciado correctamente.')

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
