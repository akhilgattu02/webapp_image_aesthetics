from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import random
import string
import sqlite3
import time, datetime

login_allowance_time = 10 #in seconds
auth = Blueprint('auth', __name__)

conn = sqlite3.connect(
    "img_db", check_same_thread=False)

conn_user = sqlite3.connect(
    "./instance/database.db", check_same_thread=False)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        #session["eml"] = email
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            cursor_user = conn_user.cursor()
            slct_string = f"SELECT * FROM sessions WHERE email = '{email}'"
            cursor_user.execute(slct_string)
            row = cursor_user.fetchone()
            if row is not None:
                login_cond = (datetime.datetime.now() - datetime.datetime.strptime(row[2],"%Y-%m-%d %H:%M:%S.%f")).total_seconds() >= login_allowance_time
            else:
                login_cond = 1
            if check_password_hash(user.password, password) and login_cond: #check last logout of the user
                
                login_time = str(datetime.datetime.now())
                if row is not None:
                    cursor_user.execute(f"UPDATE sessions SET last_login = '{login_time}' WHERE email = '{email}'")
                    conn_user.commit()
                else:
                    cursor_user.execute(f"INSERT INTO sessions (email, last_login, last_logout, user) VALUES (?, ?, ?, ?)",(email, login_time, login_time, str(-1)))
                    conn_user.commit()
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                cursor_user.execute(f"UPDATE sessions SET user = '{current_user}' WHERE email = '{email}'")
                conn_user.commit()
                return redirect(url_for('views.home'))
            else:
                if not login_cond:
                    flash(f'Please wait for {login_allowance_time}s before logging in', category='error')
                else:
                    flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    # flash('Please wait for sometime before you login again', category='failure')
    cursor_user = conn_user.cursor()
    logout_time = str(datetime.datetime.now())
    cursor_user.execute(f"UPDATE sessions SET last_logout = '{logout_time}' WHERE user = '{current_user}'")
    conn_user.commit()
    logout_user()
    login_wait = 0
    time.sleep(login_wait)
    
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        age = request.form.get('age')
        gender = request.form.get('gender')
        rod = request.form.get('rod')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First _name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'), age=age, gender=gender, rod=rod)
            db.session.add(new_user)
            db.session.commit()
            # id = db.session.execute('SELECT ID FROM USER WHERE EMAIL = {}'.format(email))
            # cur = conn.cursor()
            # cur.execute("INSERT INTO data (id, email, password, name, age, gender, rod) VALUES (?, ?, ?, ?, ?,?, ?)",
            #     (id,email, generate_password_hash(password1), first_name,age, gender,rod))
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/thankyou')
def thankyou():
    user = conn_user.cursor()
    return render_template('thankyou.html', user=user)