# app/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash
from app.models import User
from app.forms import LoginForm

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template('login.html', form=form)


@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))
