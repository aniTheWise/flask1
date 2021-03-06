from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email 
# from app import current_user
#from app import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                            validators=[DataRequired(), Length(min=2, max=20)])

    password = PasswordField('Password', 
                            validators=[DataRequired()])
    
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password')])
    
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('User is already registered! Please login.')



class LoginForm(FlaskForm):
    username = StringField('Username', 
                            validators=[DataRequired(), Length(min=2, max=20)])

    password = PasswordField('Password', 
                            validators=[DataRequired()])
    
    remember = BooleanField('Remember Me')

    submit = SubmitField('Login')  



class AddToDoForm(FlaskForm):
    thingtodo = StringField('To Do Item', 
                            validators=[DataRequired()])

    submit = SubmitField('Add')

    def validate_thingtodo(self, thingtodo):
        todoentry = todolist.query.filter_by(thingtodo=thingtodo.data).first()
        if todoentry:
            raise ValidationError('Duplicate entry')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', 
                            validators=[DataRequired(), Length(min=2, max=20)])

    email = StringField('Email', 
                         validators=[Email(), Length(min=7, max=120)])
    
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data == current_user.username:
            pass
        else:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username is already taken! Please try another.')

    def validate_email(self, email):
        if email.data == current_user.email:
            pass
        else:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email is already taken! Please try another.')

