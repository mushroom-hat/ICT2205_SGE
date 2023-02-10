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
    cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
    # Fetch one record and return result
    account = cursor.fetchone()

    if username == '' or password == '':
        return render_template('index.html', msg='Please enter username and password!')

    # If account exists n accounts table in out database
    if account:
        # Create session data accesible for other routes in flask
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        session['pubkey'] = account['pubkey']
        session['role'] = 'user' # Set the role to user

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

            cursor.execute('UPDATE accounts SET pubkey = %s, privkey = %s WHERE id = %s', (public_key_str, private_key_str, session['id']))
            mysql.connection.commit() # Commit the update
            cursor.close()

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
@app.route('/home', methods=['GET', 'POST'])
def home():
    if session['role'] == 'user':
        pass
    else:
        return redirect(url_for('index'))
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        votekey = session['pubkey']
        if votekey == None or votekey == '':
            cursor.execute('SELECT pubkey FROM accounts WHERE id = %s', (session['id'],))
            public_key_nice = cursor.fetchone()['pubkey']
        else:
            public_key_nice = votekey

        # Formatting the public key for printing later
        public_key_nice = public_key_nice.replace("-----BEGIN PUBLIC KEY-----\n", "")
        public_key_nice = public_key_nice.replace("-----END PUBLIC KEY-----\n", "")
        public_key_nice = public_key_nice.replace("\n", "")
        
        cursor.execute('SELECT * FROM candidates')
        candidates = cursor.fetchall()

        if request.method == 'POST':
            # Get the ID that use voted from POST FORM
            candidate_id = request.form['candidate_id']
            # Change print statement to whatever the system do with the vote
            print(f"User voted for candidate with ID: {candidate_id}")

        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'], candidates=candidates, public_key_nice=public_key_nice)
        cursor.close()

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
        session['role'] = 'admin' # Set the role to admin
        return render_template('adminpanel.html', username=session['username'])

    return redirect(url_for('admin'))

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