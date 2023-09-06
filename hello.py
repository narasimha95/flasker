from flask import Flask, render_template, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, DataRequired, Length, EqualTo
from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask import redirect, url_for
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user


# Create a flask instance
app = Flask(__name__)

# cross side request forgery CSRF token
app.config['SECRET_KEY'] = 'iaminevitable'

# add database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://bablu:bablu@localhost/users'

#initializse the database
db = SQLAlchemy(app)


# initialize the migrate class
migrate = Migrate(app, db)








# creating a block post model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(255))





# creating a model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    secret_key = db.Column(db.String(200), nullable=False)

    # @property
    # def password(self):
    #     raise AttributeError('Password is not a readable attribute')
    
    # @password.setter
    # def password(self, password):
    #     self.password_hash = generate_password_hash(password)
    
    # def verify_password(self, password):
    #     return check_password_hash(self.password_hash, password)
     
    # # create a string
    # def __repr__(self):
    #     return f'Name = {self.name}, Email = {self.email}'





# create a form class
class RegistrationForm(FlaskForm):
    name = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired(), Length(min=2)])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=2), EqualTo('password_hash', message="Passwords don't match")])

    secret_key = StringField('Secret Key', validators=[DataRequired()])
    submit = SubmitField('Submit')
# sample form
class PasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')
# Post form
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = StringField('Content', validators=[DataRequired()], widget=TextArea())
    author = StringField('Author', validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])
    submit = SubmitField("Submit")
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('submit')








# create a route decorater
# can i create more than one function for a single route
@app.route('/')
@app.route('/home')
def index():
    favorite_pizza = ["pepporoni", "mango", "tomato", "chocolate"]
    stuff = "heloo i am <b> bold </b>"
    first_name = "Narasimha"
    return  render_template('index.html', first_name=first_name,
                            stuff=stuff,
                             favorite_pizza=favorite_pizza)

@app.route('/date')
def current_date():
    # returning a dictonary,flask jsonifies the dictionary implicitly
    return {'Date':date.today()}


@app.route('/users/')
def users():
    our_users=Users.query.order_by(Users.date_added)
    return render_template('users.html', our_users=our_users)



# Flask login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))







@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user :
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('User login successfull')
                return redirect(url_for('dashboard'))
            else:
                flash('Wrong password, what you trying to do ? Hack ???')
        else:
            flash('Dude you dont even exist in this planet !!')


    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('you have been logout thanks for stopping by')
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = RegistrationForm()
    updated_name = Users.query.get_or_404(current_user.id)
    if request.method == 'POST':
        updated_name.username = form.name.data
        updated_name.password = generate_password_hash(form.password_hash.data, 'sha256')
        updated_name.email = request.form['email']
        updated_name.secret_key = request.form['secret_key']
        try:
            db.session.commit()
            flash('User upated succes')
            return render_template("dashboard.html", form=form, updated_name=updated_name)
        except:
            flash("Error! looks like there is a problem")
            return render_template("dashboard.html", form=form, updated_name=updated_name)
    else:
        return render_template("dashboard.html", form=form, updated_name=updated_name)
    return render_template('dashboard.html')




@app.route('/add-post', methods=['GET', 'POST'])
# @login_required
def add_post():
    form  = PostForm()

    if request.method == "POST":
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data, slug=form.slug.data)

        # clearing form
        form.content.data = ''
        form.author.data = ''
        form.title.data = ''
        form.slug.data = ''

        # add post data to database
        db.session.add(post)
        db.session.commit()

        flash('Post Added Successfully')

    return render_template('add_post.html', form=form)


@app.route('/Posts')
def posts():
    blog_posts = Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html', blog_posts=blog_posts)


@app.route('/Posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    if post :
        return render_template('post.html', post=post)
    

@app.route('/post/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if request.method == "POST" :
        post.title = form.title.data
        post.author = form.author.data
        post.content = form.content.data
        post.slug = form.slug.data
        
        # saving to the database
        db.session.commit()
        # return render_template('post.html', post=post)
        return redirect(url_for('post', id=post.id))
    form.title.data = post.title
    form.content.data = post.content
    form.slug.data = post.slug
    form.author.data = post.author
    return render_template('edit_post.html', form=form)

@app.route('/post/delete/<int:id>')
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    blog_posts = Posts.query.order_by(Posts.date_posted)
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash("Post Deleted Succesfully")
        return render_template('posts.html', blog_posts=blog_posts)
    except:
        flash("Fail to delete post")
        return render_template('posts.html', blog_posts=blog_posts)
    




@app.route('/accountstatus', methods=['GET', 'POST'])
def accountStatus():
    form = PasswordForm()
    user_to_check = ''
    status = False


    if request.method == "POST" :
        flash('Form submitted sucessfully')
        email = form.email.data
        password = request.form['password']

        # clear the form
        form.email.data = ''
        form.password.data = ''

        # retriev the data
        user_to_check = Users.query.filter_by(email=email).first()

        # check the password
        if user_to_check:
            status = check_password_hash(user_to_check.password, password)
        




    return render_template('sample.html', form=form, user_to_check=user_to_check, status=status)


@app.route('/adduser', methods=['GET', 'POST'])
def adduser():
    form = RegistrationForm()
    name = ''
    our_users = Users.query.order_by(Users.date_added)
    if  form.validate_on_submit():
        user  = Users.query.filter_by(email=form.email.data).first()
        if user is None :
            # hash the password
            hashed_pwd = generate_password_hash(form.password_hash.data, "sha256")
            user_obj = Users(username=form.name.data, password=hashed_pwd, email=form.email.data, secret_key=form.secret_key.data)
            db.session.add(user_obj)
            db.session.commit()
            name = form.name.data
            form.name.data=''
            form.email.data=''
            form.password_hash.data = ''
            form.secret_key.data = ''
            our_users = Users.query.order_by(Users.date_added)
            flash("User Added")
        
        else:
            form.name.data=''
            form.email.data=''
            form.password_hash.data = ''
            form.secret_key.data = ''
            flash("email already exist")
    
    return render_template('adduser.html', form=form, our_users=our_users)










@app.route('/update/<int:id>', methods=['POST', 'GET'])
def update(id):
    form = RegistrationForm()
    updated_name = Users.query.get_or_404(id)
    if request.method == 'POST':
        updated_name.username = form.name.data
        updated_name.password = generate_password_hash(form.password_hash.data, 'sha256')
        updated_name.email = request.form['email']
        updated_name.secret_key = request.form['secret_key']
        try:
            db.session.commit()
            flash('User upated succes')
            return render_template("update.html", form=form, updated_name=updated_name)
        except:
            flash("Error! looks like there is a problem")
            return render_template("update.html", form=form, updated_name=updated_name)
    else:
        return render_template("update.html", form=form, updated_name=updated_name)


@app.route('/delete/<int:id>')
def delete(id) :
    user_to_delete = Users.query.get_or_404(id)
    form = RegistrationForm()

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('user deleted sucessfully')
    except:
        flash('Error occured while deleting a user, check your code again')
    
    our_users = Users.query.order_by(Users.date_added)
    return render_template('adduser.html',form=form, our_users=our_users)































# Error handling mechanisms

# routing for invalid urls
@app.errorhandler(404)
def page_not_found(e):
    return render_template("error.html"), 404

# for server failute
@app.errorhandler(500)
def page_not_found(e):
    return render_template("error.html"), 500