from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from .models import User
from .forms import LoginForm, TOTPForm
from . import db
import pyotp
from flask_qrcode import QRcode

main = Blueprint('main', __name__)


@main.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    totp_form = TOTPForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['pre_mfa_userid'] = user.id
            if user.totp_secret:
                return redirect(url_for('main.mfa_verify'))
            else:
                login_user(user, fresh=True)
                flash("Login successful!", "success")
                if not user.totp_secret:
                    return redirect(url_for('main.mfa_setup'))
                return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid username or password.", "danger")


    return render_template('login.html', form=form)


@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


@main.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))

@main.route('/mfa_setup')
@login_required
def mfa_setup():
    user = current_user
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp_uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
        name=user.username,
        issuer_name="SecureFlaskApp"
    )
    return render_template('mfa_setup.html', uri=totp_uri, secret=user.totp_secret)

@main.route('/mfa_verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pre_mfa_userid' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['pre_mfa_userid'])
    form = TOTPForm()

    if form.validate_on_submit():
        totp_code = form.totp_code.data
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_code):
            login_user(user, fresh=True)
            session.pop('pre_mfa_userid', None)
            flash("Login successful!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid TOTP code.", "danger")

    return render_template('mfa_verify.html', form=form)
