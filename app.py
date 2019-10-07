#external imports
from flask import Flask, render_template, request, redirect, flash, url_for, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from PIL import Image
#----------------------------------------------------------------------------------------
#forms imports 
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email 
#----------------------------------------------------------------------------------------
#standard libray imports
from datetime import date
from datetime import datetime
import json
# import secrets
import os, string, random
import http.client
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
    
    things_to_do = dba.relationship('todolist', backref='owner', lazy=True)
    image = dba.relationship('Images', backref='owner', lazy=True)

    def __repr__(self):
        return "User('{}', '{}', '{}', '{}')".format(self.username, 
                                                     self.email, 
                                                     self.things_to_do,
                                                     self.image)

class todolist(dba.Model):
    id = dba.Column(dba.Integer, primary_key=True)
    thingtodo = dba.Column(dba.String(50), nullable=False)
    created = dba.Column(dba.DateTime, nullable=False, default=datetime.now)

    user_id = dba.Column(dba.Integer, dba.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return "todolist(thingtodo='{}', user_id='{}'".format(self.thingtodo, 
                                                              self.user_id)

class Images(dba.Model):
    id = dba.Column(dba.Integer, primary_key=True)
    picture_file = dba.Column(dba.String(20), nullable=True, default="default.jpg")
    user_id = dba.Column(dba.Integer, dba.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return "Images(picture_file='{}', user_id='{}')".format(self.picture_file, 
                                                                self.user_id)

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
                         validators=[Email()])

    picture = FileField('Update Profile Picture', 
                        validators=[FileAllowed(['jpg', 'png'])])
    
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

#----------------------------------------------------------------------------------------


#routes
@app.route('/')
def index():
    # return redirect(url_for('todo'))
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
    # print(type(all_articles))
    # print(all_articles['articles'][0]['publishedAt'])
    # print(type(all_articles['articles'][0]['publishedAt']))
    # n=all_articles['articles'][0]['publishedAt']

    if all_articles:
        for each in all_articles['articles']:
            n = each['publishedAt']
            each['publishedAt'] = datetime( int(n[:4]),
                                            int(n[5:7]),
                                            int(n[8:10]),
                                            hour=int(n[11:13]),
                                            minute=int(n[14:16]), 
                                            second=int(n[17:19]))
                                        

    return render_template('getnews.html',
                            news=enumerate(all_articles['articles']), 
                            num_art=len(all_articles['articles']),
                            title="World News"
    )

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



def save_picture(form_picture):
    random_hex = ''.join([random.choice(string.ascii_lowercase) for x in range(8)])
    # random_hex = secrets.token_hex(8)
    # f_name, f_ext = os.path.splitext(form_picture.filename)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn =  random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    
    #Pillow module image resizing
    output_size = (225,225)
    i = Image.open(form_picture)    
    i.thumbnail(output_size)
    i.save(picture_path)
    # form_picture.save(picture_path)

    return picture_fn


@app.route('/account', methods=["GET", "POST"])
@login_required
def account():
    form = UpdateAccountForm()
    #if form is submitted (POST stuff)
    if form.validate_on_submit():

        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            image_file = Images.query.filter_by(user_id=current_user.id).first()
            image_file.picture_file = picture_file

        current_user.username = form.username.data
        current_user.email = form.email.data
        dba.session.commit()
        flash("Account Info updated successfully!", "success")
        return redirect(url_for('account'))
    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', 
                         filename='profile_pics/' + 
                         Images.query.filter_by(user_id=current_user.id).first()
                         .picture_file)    
    # 
    # image_file = url_for('static', filename='profile_pics/'+current_user.username+'.jpg')
    #  
    # image_file = url_for('static', filename='profile_pics/default.jpg')
    # 
    return render_template('account.html', image_file=image_file, form=form)



@app.route('/todo', methods=['GET', 'POST'])
@login_required
def todo():
    form = AddToDoForm()

    if request.method == 'POST':
        new_todo = todolist(thingtodo=form.thingtodo.data, user_id=current_user.id)
        dba.session.add(new_todo)
        dba.session.commit()
        flash('To Do List updated!', 'success')
        return redirect(url_for('todo'))
    #else
    # todo_list = todolist.query.all()
    todo_list = current_user.things_to_do

    return render_template('todo.html', 
                            title=current_user.username +"'s To-Do List", 
                            todo_list=todo_list, form=form)



@app.route('/todo/<int:todo_id>/delete', methods=['POST'])
@login_required
def delete_todo(todo_id):
    todo_item = todolist.query.get_or_404(todo_id)
    print(todo_id)
    # if todo.author != current_user:
    #     abort(403)
    dba.session.delete(todo_item)
    dba.session.commit()
    flash('To Do item deleted!', 'info')
    return redirect('todo')



@app.route('/cb_sportradar')
def cb_sportradar():

    # import http.client
    # api key for api.sportradar.us
    # username: AniAni
    # reg email: kingoftennis94...
    # reg app: flask1

    # tennis_t2_api_key = 'fkbtucsybrvwj7rg76pnvkp5'

    tennis_t2_api_key = 'fkbtucsybrvwj7rg76pnvkp5'
    
    conn = http.client.HTTPSConnection("api.sportradar.us")
    conn.request("GET", "/tennis-{access_level}{version}/{language_code}/schedules/{year}-{month}-{day}/results.{format}?api_key={tennis_t2_api_key}".format(
        access_level="t",	#Production (p) or Trial (t).
        version="2",	        #Whole number (Current Version: 2).
        language_code="en",	#List of Supported Locales
        year="2019",	        #Year in 4 digit format (YYYY).
        month="10",	        #Month in 2 digit format (MM).
        day="01",	            #Day of the month in 2 digit format (DD).
        # live="",        	#Optional: In place of the date, substitute live for the current live results.
        format="json",	        #xml or json.
        tennis_t2_api_key = 'fkbtucsybrvwj7rg76pnvkp5'
    ))

    res = conn.getresponse()
    data = res.read()

    print(data.decode("utf-8"))

    return data.decode("utf-8")



#----------------------------------------------------------------------------------------

#app run
if __name__ == '__main__':
        app.run(host='192.168.1.92', debug=True)
#----------------------------------------------------------------------------------------