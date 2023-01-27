from flask import Flask, render_template, redirect, url_for, request, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = '123456'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'P@ssw0rd123'
app.config['MYSQL_DB'] = 'pythonlogin'

# Intialize MySQL
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('index.html')

# http://localhost:5000/pythonlogin/ - the following will be our login page, which will use both GET and POST requests
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    username = ''
    password = ''
    
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']

    # Check if account exists using MySQL
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
    # Fetch one record and return result
    account = cursor.fetchone()

    if username == '' or password == '':
        return render_template('index.html', msg='Please enter username and password!')

    # If account exists n accounts table in out database
    if account:
        # Create session data, we can access this data in other routes
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        session['pubkey'] = account['pubkey']

        if session['pubkey'] == None or session['pubkey'] == '':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # Convert private key to string
            private_key_str = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

            public_key = private_key.public_key()

            # Convert public key to string
            public_key_str = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            # Formatting the key into 1 line
            public_key_str = public_key_str.replace("-----BEGIN PUBLIC KEY-----\n", "")
            public_key_str = public_key_str.replace("-----END PUBLIC KEY-----\n", "")
            public_key_str = public_key_str.replace("\n", "")

            private_key_str = private_key_str.replace("-----BEGIN PRIVATE KEY-----\n", "")
            private_key_str = private_key_str.replace("-----END PRIVATE KEY-----\n", "")
            private_key_str = private_key_str.replace("\n", "")

            print('Public key:', public_key_str)
            print('Private key:', private_key_str)
            print('Session ID:', session['id'])

            cursor.execute('UPDATE accounts SET pubkey = %s, privkey = %s WHERE id = %s', (public_key_str, private_key_str, session['id']))
            mysql.connection.commit() # Commit the update
            cursor.close()

        # Redirect to home page
        return redirect(url_for('home'))
    else:
        # Account doesnt exist or username/password incorrect
        return render_template('index.html', msg='Incorrect username or password!')
    
    # Show the login form with message (if any)
    return render_template('index.html', msg='Strange Error Occured!')

    # http://localhost:5000/python/logout - this will be the logout page
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return render_template('index.html', msg='')

# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        votekey = session['pubkey']
        if votekey == None or votekey == '':
            cursor.execute('SELECT pubkey FROM accounts WHERE id = %s', (session['id'],))
            votekey = cursor.fetchone()['pubkey']
        cursor.execute('SELECT * FROM candidates')
        candidates = cursor.fetchall()

        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'], candidates=candidates, votekey=votekey)

        cursor.close()

    # User is not loggedin redirect to login page
    return redirect(url_for('index'))