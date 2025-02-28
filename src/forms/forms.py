from flask_wtf import FlaskForm
from wtforms import EmailField, StringField, PasswordField, ValidationError, SubmitField

class Register(FlaskForm):
    username = StringField('Nombre de usuario')
    email = EmailField('Correo electrónico')
    contrasenya = PasswordField('Contraseña')
    enviar = SubmitField('Registrarse')

class Login(FlaskForm):
    email = EmailField('Correo electrónico')
    contrasenya = PasswordField('Cntraseña')
    enviar = SubmitField('Registrarse')
