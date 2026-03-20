import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_security import login_required
from flask_security.utils import login_user, logout_user

from .models import User
from . import db, user_datastore

auth = Blueprint('auth', __name__, url_prefix='/security')


@auth.route('/login')
def login():
    return render_template('/security/login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        # LOG: Intento de acceso fallido
        logging.warning(
            f'EVENTO: LOGIN_FALLIDO | EMAIL: {email} | IP: {request.remote_addr}'
        )
        flash('El email y/o contrasena son incorrectos')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)

    # LOG: Login exitoso
    logging.info(
        f'EVENTO: LOGIN | USUARIO_ID: {user.id} | EMAIL: {user.email} | NOMBRE: {user.name} | IP: {request.remote_addr}'
    )

    return redirect(url_for('main.profile'))


@auth.route('/register')
def register():
    return render_template('/security/register.html')


@auth.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        # LOG: Registro fallido por email duplicado
        logging.warning(
            f'EVENTO: REGISTRO_FALLIDO | EMAIL: {email} | MOTIVO: Email ya existente | IP: {request.remote_addr}'
        )
        flash('Ese correo electronico ya existe')
        return redirect(url_for('auth.register'))

    try:
        user_datastore.create_user(
            name=name,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.commit()

        # LOG: Registro exitoso
        logging.info(
            f'EVENTO: REGISTRO | EMAIL: {email} | NOMBRE: {name} | IP: {request.remote_addr}'
        )

    except Exception as e:
        db.session.rollback()
        # LOG: Error al registrar
        logging.error(
            f'EVENTO: ERROR | EMAIL: {email} | DETALLE: {str(e)} | IP: {request.remote_addr}'
        )
        flash('Ocurrio un error al registrar el usuario. Intenta de nuevo.')
        return redirect(url_for('auth.register'))

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    from flask_security import current_user

    # LOG: Cierre de sesion
    logging.info(
        f'EVENTO: LOGOUT | USUARIO_ID: {current_user.id} | EMAIL: {current_user.email} | NOMBRE: {current_user.name} | IP: {request.remote_addr}'
    )

    logout_user()
    return redirect(url_for('main.index'))