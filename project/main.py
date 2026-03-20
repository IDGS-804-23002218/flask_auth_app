from flask import Blueprint, render_template
from flask_security import current_user, login_required
from flask_security.decorators import roles_required

from . import db

main = Blueprint('main',__name__)

#definimos la ruta principal /
@main.route('/')
def index():
    return render_template('index.html')

#definimos la ruta de la pagina del perfil
@main.route('/profile')
@login_required
@roles_required('admin')
def profile():
    return render_template('profile.html', name=current_user.name)