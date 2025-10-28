from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Optional


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=30)],
        render_kw={"placeholder": "Enter your username"}
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=6, max=128)],
        render_kw={"placeholder": "Enter your password"}
    )
    recaptcha = RecaptchaField()
    submit = SubmitField("Login")

class TOTPForm(FlaskForm):
    totp_code = StringField("TOTP Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")