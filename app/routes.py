from datetime import timedelta, datetime

from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from wtforms.validators import DataRequired
from .models import User
from .forms import LoginForm, TOTPForm
from . import db, limiter
import pyotp

main = Blueprint('main', __name__)
MAX_FAILED = 5
LOCKOUT_DURATION = timedelta(minutes=5)
CAPTCHA_THRESHOLD = 3


@main.route('/', methods=['GET', 'POST'])
@limiter.limit("7 per minute", error_message="Too many login attempts. Try again in a minute.")
def login():
    form = LoginForm()
    user = None

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        require_captcha = user and user.failed_attempts >= CAPTCHA_THRESHOLD

        if require_captcha:
            form.recaptcha.validators = [DataRequired(message="Please complete the CAPTCHA.")]
        else:
            form.recaptcha.validators = []

        if not form.validate():
            return render_template('login.html', form=form, show_captcha=require_captcha)

        if user:
            if user.lockout_until and datetime.utcnow() < user.lockout_until:
                remaining = (user.lockout_until - datetime.utcnow()).seconds // 60 + 1
                flash(f"Account locked. Try again in {remaining} minute(s).", "danger")
                return redirect(url_for('main.login'))

            if user.check_password(password):
                user.failed_attempts = 0
                user.lockout_until = None
                db.session.commit()

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
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_FAILED:
                    user.lockout_until = datetime.utcnow() + LOCKOUT_DURATION
                    flash("Too many failed attempts. Account locked for 5 minutes.", "danger")
                else:
                    flash("Invalid username or password.", "danger")
                db.session.commit()
        else:
            flash("Invalid username or password.", "danger")

    show_captcha = user and user.failed_attempts >= CAPTCHA_THRESHOLD
    return render_template('login.html', form=form, show_captcha=show_captcha)

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
