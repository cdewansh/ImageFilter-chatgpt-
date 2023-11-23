from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask import Flask, render_template, url_for, redirect, flash, request,jsonify
from flask_sqlalchemy import SQLAlchemy

# def run_database():
#     global db
#     db = SQLAlchemy()  
# 
# # SQLAlchemy initialized here
db = SQLAlchemy()


# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=True)
    phoneNumber = db.Column(db.String(15), nullable = True)


# Define registration form
class RegisterForm(FlaskForm):
    # Form fields with validators and placeholders
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    email = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    phoneNumber = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "PhoneNumber"})
    submit = SubmitField("Register")

    # Custom validation for username uniqueness
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            flash("That username already exists. Please choose a different one.")
            raise ValidationError('That username already exists. Please choose a different one.')


# Define login form
class LoginForm(FlaskForm):
    # Form fields with validators and placeholders
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

    def validate_username(self, username):
        # Check if the user exists in the database
        existing_user = User.query.filter_by(username=username.data).first()

        if not existing_user:
            # Flash a message if the user doesn't exist
            flash("User does not exist. Please sign up.")
            raise ValidationError('User does not exist. Please sign up.')
