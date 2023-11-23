# Import necessary modules
import sqlite3
from flask import Flask, render_template, url_for, redirect, flash, request,jsonify
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from database import *
from ImageProcessing import *
import cv2 
import os
import aiapi



# Initialize Flask app

# db = SQLAlchemy()  # SQLAlchemy initialized in database.py

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configure app settings
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db.init_app(app)
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Login route
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

# Dashboard route with login required
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('index.html')

# Edit route with file upload and processing
@app.route('/edit', methods=["GET", "POST"])
@login_required
def edit():
    if request.method == 'POST':
        operation = request.form.get("operation")
        if 'file' not in request.files:
            flash('No file part')
            return "error"
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return "error on selected file"
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new = processImage(filename, operation)
            flash(f"Your image has been processed <a href='/{new}'target='_blank'>View Online</a> and  <a href='/{new}' target='_blank' download='{new}' class='btn btn-success'>DOWNLOAD</a>")
            # flash(f"Your image has been processed and download from here  <a href='/{new}' target='_blank' download='{new}' class='btn btn-primary'>DOWNLOAD</a>")
            return render_template("index.html")
    return render_template("index.html")

# Logout route
@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Register route
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, phoneNumber=form.phoneNumber.data)
        db.session.add(new_user)
        db.session.commit()
        #For closing the db
        db.session.close()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/use')
def use():
    return render_template('use.html')

# Update email route
@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    if request.method == 'POST':
        new_email = request.form.get('new_email')
        if new_email:
            current_user.email = new_email
            db.session.commit()
            flash('Email updated successfully', 'success')
        else:
            flash('Invalid email', 'error')
    return redirect(url_for('profile'))

@app.route('/update_email_form')
@login_required
def update_email_form():
    return render_template('update_email_form.html')

@app.route('/profile')
@login_required  # Ensure the user is logged in to access the profile
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/delete_user/<string:username>', methods=['POST'])
def delete_user(username):
    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()

    # Delete the user with the specified ID
    cursor.execute('DELETE FROM user WHERE username = ?', (username,))
    conn.commit()

    conn.close()

    return redirect(url_for('home'))

@app.route('/chat',methods =['POST','GET'])
@login_required
def chat():
    if request.method == 'POST':
        prompt = request.form['prompt']
        res={}
        res['answer'] = aiapi.generateChatResponse(prompt)
        return jsonify(res),200
    return render_template('chat.html',**locals())




# Run the app if executed as the main script
if __name__ == "__main__":
    app.run(debug=True)
