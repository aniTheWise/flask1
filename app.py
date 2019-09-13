#external imports
from flask import Flask, render_template, request, redirect, flash, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
#----------------------------------------------------------------------------------------
#forms imports 
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError 
#----------------------------------------------------------------------------------------
#standard libray imports
from datetime import date
#----------------------------------------------------------------------------------------
#Ani specfic imports
import sqlite3
from newsapi import NewsApiClient
#----------------------------------------------------------------------------------------
#this line is for later
#from forms import RegistrationForm, LoginForm

#initializations
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a28cbc160a5f19ca175d7a08660e0946'
#app.secret_key = 'a28cbc160a5f19ca175d7a08660e0946'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = sqlite3.connect('testdb1.db', check_same_thread=False)
dba = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_required.login_view = 'login'
login_required.login_message_category = 'info'
#----------------------------------------------------------------------------------------

#models

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(dba.Model, UserMixin):
    id = dba.Column(dba.Integer, primary_key=True)
    username = dba.Column(dba.String(20), unique=True, nullable=False)
    password = dba.Column(dba.String(60), nullable=False)
    email = dba.Column(dba.String(120), nullable=True)

#    def __repr__(self):
#        return "User('{}', '{}', '{}')".format(self.id, self.username, self.password)
#----------------------------------------------------------------------------------------

#forms

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
#----------------------------------------------------------------------------------------


#routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sqlinput')
def sql_input():
    try:
        query = '''SELECT * FROM todo_list'''
        db_out = db.execute(query).fetchall()
    except sqlite3.Error as err:
        print('sql error:', err)
        flash(err)
        db_out = None

    data = []
    if db_out:
        for i in db_out:
            data.append('{:_<3} | {:_<100} {}'.format(i[0], i[1], i[2]))

    return render_template('sql_input.html', data=data)

@app.route('/execsql', methods=['POST'])
def execsql():
    fi = request.form['sql']
    print(fi)
    try:
        db.execute(fi)
        db.commit()
    except sqlite3.Error as err:
        print('sql error:', err)
        err = str(err)
        flash(err)

    return redirect('/sqlinput')

@app.route('/getnews/<in_type>', methods=['GET', 'POST'])
def getnews(in_type):
        
    # Api Init
    newsapi = NewsApiClient(api_key='6a3bae9eac704ed4b9ff1412f69c37b1')
   
    if request.method == 'POST':
        #try:
        in_q          = request.form['q']
        in_sources    = request.form['sources']
        in_domains    = request.form['domains']
        in_from_param = request.form['from_param']
        in_to         = request.form['to']
    else:
        in_q          = 'trump'
        in_sources    = 'bbc-news'
        in_domains    = 'bbc.co.uk'
        in_from_param = date.today().isoformat()
        in_to         = '2019-08-01'

    print(in_q, in_sources, in_domains, in_from_param, in_to)
    


    if in_type == 'all_articles':
        all_articles = newsapi.get_everything(q=in_q,
                                            sources=in_sources,
                                            domains=in_domains,
                                            from_param=in_from_param,
                                            to=in_to,
                                            language='en',
                                            sort_by='relevancy',
                                            page=2)
    elif in_type == 'top_headlines':
        all_articles = newsapi.get_top_headlines(#q='trump',
                                          #sources='bbc-news,the-verge',
                                          category='business',
                                          language='en',
                                          country='in')
    else:
        return 'no clue man'
    print(all_articles)
    return render_template('getnews.html', news=all_articles)

@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        flash('A registered user is logged in', 'info')
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        dba.session.add(user)
        dba.session.commit()
        flash("Your account has been created, you can now login", "success")
        return redirect(url_for('login'))

    return render_template('register.html', title='Register' , form=form)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        flash('User is already logged in', 'info')
        return redirect(url_for('index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Welcome {}, you have logged in successfully".format(user.username), "success")
            next_page = request.args.get('next')
            return redirect(url_for(next_page)) if next_page else redirect(url_for('index'))
        else:
            flash("Login unsuccessful, Please check the Username and Password", "danger")
    return render_template('login.html', title='Login' , form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Logout Successful', 'info')
    return redirect(url_for('index'))



@app.route('/account')
@login_required
def account():
    return render_template('account.html', title="Account")


#----------------------------------------------------------------------------------------

#app run
if __name__ == '__main__':
        app.run(host='192.168.1.9', debug=True)
#----------------------------------------------------------------------------------------