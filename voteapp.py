import json

import requests
from flask import Flask, render_template, redirect, url_for, request, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from functools import wraps

import hashlib
import secrets

app = Flask(__name__)

# Use for generating sessionID for encryption
app.secret_key = 'psoadkaspodj@aspdjaspo123dfas3489rdj!!#!@!4112312903u213u9812' # Randomly typed on my keyboard basically uncrackable

# Configure session cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True

# Enter your database connection details below
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = "P@ssw0rd123"
app.config['MYSQL_DB'] = 'pythonlogin'

# Intialize MySQL
mysql = MySQL(app)


@app.route('/')
def index():
    # Create accounts. Username is same as password.
    accounts = ["minyao", "ruiheng", "zhenghao", "zhiwen", "jiazhe"]

    for acc in accounts:
        username = password = acc

        # Check if account already exists in MySQL DB
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists!'
        else:
            # Hash the password with the salt
            salt = secrets.token_hex(96)
            salted_password = (salt + password).encode('utf-8')
            hashed_password = hashlib.sha512(salted_password).hexdigest()

            # Insert new account into MySQL DB
            cursor.execute('INSERT INTO accounts (username, password, salt) VALUES (%s, %s, %s)',
                           (username, hashed_password, salt))
            mysql.connection.commit()
            cursor.close()

            msg = 'Account created successfully!'

    return render_template('index.html')

# Decorator function to redirect if user is not logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') is None or session.get('loggedin') is not True:
            return redirect('/login',code=302)
        return f(*args, **kwargs)
    return decorated_function

# http://localhost:5000/pythonlogin/ - the following will be our login page, which will use both GET and POST requests
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Output message if authentication error
    msg = ''
    username = ''
    password = ''

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']

    # Checking if account exists in MySQL DB (All queries parametererized to prevent SQL injection)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
    # Fetch one record and return result
    account = cursor.fetchone()

    if username == '' or password == '':
        return render_template('index.html', msg='Please enter username and password!')

    # If account exists n accounts table in out database
    if account:
        # Hash the password with the salt from the database and use SHA-512
        salted_password = (account['salt'] + password).encode('utf-8')
        hashed_password = hashlib.sha512(salted_password).hexdigest()
        if hashed_password == account['password']:
            # Create session data accesible for other routes in flask
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = 'user'  # Set the role to user

        # Redirect to home page after successful login
        return redirect(url_for('home'))
    else:
        # If account doesnt exist or username/password incorrect
        return render_template('index.html', msg='Incorrect username or password!')

    # If it reaches here, some weird and unexpected error occured
    return render_template('index.html', msg='Strange Error Occured!')


# http://localhost:5000/logout - this will be the logout page
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return render_template('index.html', msg='')


# http://localhost:5000/home - this will be the home voting page, only accessible for loggedin users
@app.route('/home', methods=['GET'])
def home():
    if session['role'] == 'user':
        pass
    else:
        return redirect(url_for('index'))
    # Check if user is loggedin
    if 'loggedin' in session:
        id = session['id']
        voteFlag = 0
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM candidates')
        candidates = cursor.fetchall()

        cursor.execute(f'SELECT ciphertext1 FROM accounts WHERE id = {id}')
        if cursor.fetchone()['ciphertext1'] != None:
            voteFlag = 1
        cursor.close()
        
        # Dynamic public key values from json file to render in home page
        with open('pubpg.json', 'r') as pubfile:
            pubpg = json.load(pubfile)
        combined_pub = pubpg['combined_pub']
        p = pubpg['p']
        g = pubpg['g']
        print(combined_pub)

        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'], candidates=candidates, voteFlag=voteFlag, combined_pub=combined_pub, p=p, g=g)
        
    # User is not loggedin redirect to login page
    return redirect(url_for('index'))


@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    # Output message if authentication error
    msg = ''
    username = ''
    password = ''

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']

    # Checking if account exists in MySQL DB (All queries parametererized to prevent SQL injection)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM tabulator WHERE tabulatorid = %s AND tabulatorpass = %s', (username, password))
    # Fetch one record and return result
    admin_account = cursor.fetchone()

    if username == '' or password == '':
        return render_template('index.html', msg='Please enter username and password!')

    # If account exists n accounts table in out database
    if admin_account:
        # Create session data accesible for other routes in flask
        session['loggedin'] = True
        session['username'] = admin_account['tabulatorid']
        session['role'] = 'admin'  # Set the role to admin
        return render_template('adminpanel.html', username=session['username'])

    return redirect(url_for('admin'))

@app.route('/vote_success')
@login_required
def vote_success():
    id = session['id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute(f'SELECT ciphertext1 FROM accounts WHERE id = {id}')
    if cursor.fetchone()['ciphertext1'] == None:
        cursor.close()
        return redirect(url_for('home'))

    return render_template('vote_success.html', username=session['username'])


@app.route('/sendVote', methods=['POST'])
@login_required
def serverReceiveVote():
    if session['role'] == 'user' and session['loggedin'] == True and session['id']:
        data = request.json
        cipher1 = data['c1']
        cipher2 = data['c2']
        cipher3 = data['c3']

        # Each of the ciphertext stored in this format cpart1,cpart2
        formatC1 = cipher1[0] + ',' + cipher1[1]
        formatC2 = cipher2[0] + ',' + cipher2[1]
        formatC3 = cipher3[0] + ',' + cipher3[1]

        id = session['id']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(f'SELECT ciphertext1 FROM accounts WHERE id = {id}')
        if cursor.fetchone()['ciphertext1'] != None:
            print("Vote already registered, this won't be counted")
            pass
        else:
            cursor.execute(f'UPDATE accounts SET ciphertext1 = "{formatC1}", ciphertext2 = "{formatC2}", ciphertext3 = "{formatC3}" WHERE id = {id}')
            mysql.connection.commit()
        cursor.close()
    return redirect(url_for('vote_success'))

@app.route('/adminpanel', methods=['GET', 'POST'])
def adminpanel():
    if session['role'] == 'admin':
        pass
    else:
        return redirect(url_for('index'))
    if 'loggedin' in session:
        # cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # cursor.execute('SELECT * FROM candidates')
        # candidates = cursor.fetchall()
        # cursor.execute('SELECT * FROM accounts')
        # accounts = cursor.fetchall()
        # cursor.execute('SELECT * FROM tabulator')
        # tabulator = cursor.fetchall()
        # return render_template('adminpanel.html', candidates=candidates, accounts=accounts, tabulator=tabulator)
        return render_template('adminpanel.html', username=session['username'])
    else:
        return redirect(url_for('adminlogin'))


# Specifying our self signed SSL certificate (Realisticly should pay for a real one, self signed for demo purposes)
if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
