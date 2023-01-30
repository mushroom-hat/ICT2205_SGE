Install these: 
pip3 install Flask-MySQLdb
pip install flask
pip install cryptography

Install MySQL Server and Workbench:
https://dev.mysql.com/downloads/windows/installer/8.0.html
(Use the above installer to install mysqlserver and workbench)

To run flask (on windows):
set FLASK_APP=voteapp.py
set FLASK_DEBUG=1
flask run --cert=cert.pem --key=key.pem

execute the queries login_query.sql and candidate_query.sql in MySQL