from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/Toby')
def toby():
    return render_template("Toby-Burton.html", user=current_user)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))

            else:
                flash('Incorrect password, try again', category='error')

        else:
            flash('Email does not exist', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/signup', methods=['GET', 'POST'])
def sign_up():
    if request.method =='POST':
        email = request.form.get('email')
        first_name = request.form.get('firstname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists, login', category='error')

        elif len(email) < 4:
            flash('Email must be greater then 4 characters', category='error')
        elif len(first_name) <2:
            flash('Email must be greater then 1 characters', category='error')
        elif password1 != password2:
            flash('Your passwords dont match', category='error')
        elif len(password1) < 7:
            flash('Your password must be 7 characters or greater', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign-up.html", user=current_user)

@auth.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method =='POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        middlename = request.form.get('middlename')
        lastname = request.form.get('lastname')
        age = request.form.get('age')
        birthday = request.form.get('birthday')
        extrainfo = request.form.get('extrainfo')


    return render_template("submit.html")



