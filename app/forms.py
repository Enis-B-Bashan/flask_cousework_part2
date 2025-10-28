from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

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
    submit = SubmitField("Login")

class TOTPForm(FlaskForm):
    totp_code = StringField("TOTP Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")