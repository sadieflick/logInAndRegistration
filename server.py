from flask import Flask, render_template, redirect, session, request, flash, url_for
# import the function connectToMySQL from the file mysqlconnection.py
from flask_bcrypt import Bcrypt
from mySQLconnection import connectToMySQL
import re

app = Flask(__name__)
bcrypt = Bcrypt(app) 

app.secret_key = "keepItSecretKeepItSafe"

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# invoke the connectToMySQL function and pass it the name of the database we're using
# connectToMySQL returns an instance of MySQLConnection, which we will store in the variable 'mysql'
mysql = connectToMySQL('logInAndRegistration')
# now, we may invoke the query_db method
#print("all the users", mysql.query_db("SELECT * FROM friends;"))

@app.route('/')
def index():

    if "email" in session or "first_name" in session or "last_name" in session:
        return render_template('index.html', email = session["email"], last_name=session["last_name"], first_name=session["first_name"])
    else:
        
        return render_template('index.html')


@app.route('/success')
def success():

    if "successMessage" not in session:
        flash("You must be logged in to enter site.")
        return redirect('/')

    return render_template('success.html', successMessage = session["successMessage"], first_name= session["first_name"])


@app.route('/register', methods=['POST'])
def submit():

    session["first_name"] = request.form["first_name"]
    session["last_name"] = request.form["last_name"]
    session["email"] = request.form["email"]
    password = request.form["password"]

    if len(request.form['email']) < 1 or len(request.form['first_name']) < 1 or len(request.form['last_name']) < 1 or len(request.form['password']) < 1:
        flash("All fields required")
        return redirect('/')

    if not request.form['first_name'].isalpha() or not request.form['last_name'].isalpha():
        flash("Name must only contain letters.")
        return redirect('/')
    
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid email address.")
        return redirect('/')
    if request.form['password'] != request.form["password2"]:
        flash("Passwords do not match")
        return redirect('/')
    x = request.form['password']
    if not re.search('\d.*[A-Z]|[A-Z].*\d', x):
        flash("Password must contain at least 1 uppercase letter and 1 number.")
        return redirect('/')
    

    searchQuery = "SELECT email FROM users WHERE email = %(email)s;"
    data = { 'email': request.form['email'] }
    alreadyInDB = mysql.query_db(searchQuery, data)

    if alreadyInDB:
        flash("Sign up unsuccessful. Account already exists.")
        return redirect ('/')
    else:
        print("did not find matching email")

        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        print(pw_hash)

        query2 = "INSERT INTO users (email, first_name, last_name, password) VALUES (%(email)s, %(first_name)s, %(last_name)s, %(password_hash)s);"
        data = {
                'email': request.form['email'],
                'first_name': request.form['first_name'],
                'last_name': request.form['last_name'],
                'password_hash': pw_hash
            }

        mysql.query_db(query2, data)

        session["successMessage"] = "registered"
        session["loggedIn"] = "true"
        return redirect("/success")

@app.route("/login", methods = ["POST"])
def login():


    searchQuery = "SELECT * FROM users WHERE email = %(email)s;"
    data = { 'email': request.form['email'] }
    emailAlreadyInDB = mysql.query_db(searchQuery, data)

    if emailAlreadyInDB:
        if bcrypt.check_password_hash(emailAlreadyInDB[0]['password'], request.form['password']):

        # Get first name to return in success log in in Session
            query = "SELECT first_name FROM users WHERE email = %(email)s;"
            data = { 'email': request.form['email']}
            session["first_name"] = mysql.query_db(query, data)[0]["first_name"]

            session["loggedIn"] = "true"
            session["successMessage"] = "logged in"

        return redirect("/success")
    else:
        flash("Log in unsuccessful")
        return redirect("/")

@app.route("/logout")
def logout():
    
    session.clear()
    flash("You have been logged out.")
    session["loggedin"] = "false"
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
