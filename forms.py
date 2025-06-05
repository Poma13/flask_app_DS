from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.file import FileField, FileAllowed


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=4, max=100)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password")])


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class ProfileForm(FlaskForm):
    avatar = FileField('Аватар', validators=[FileAllowed(['jpg', 'png', 'gif'])])
    banner = FileField('Баннер', validators=[FileAllowed(['jpg', 'png', 'gif'])])
    submit = SubmitField('Обновить профиль')

class CreateServerForm(FlaskForm):
    name = StringField('Название сервера', validators=[
        DataRequired(),
        Length(min=3, max=50)
    ], render_kw={"placeholder": "Только буквы и цифры"})
    members = SelectMultipleField('Выберите друзей',
                                coerce=int,
                                render_kw={"class": "friend-select"})
    submit = SubmitField('Создать сервер')