import os
from flask import Flask, render_template, request, redirect, url_for, flash
from auth_utils import generate_signature, verify_signature

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Store user credentials
user_data = {}

@app.route('/')
def landing():
    """Landing page with options to sign up or sign in."""
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Register new user
        if username in user_data:
            flash("User already exists. Please sign in instead.")
        else:
            public_key, signature, salt = generate_signature(password)
            user_data[username] = {
                'public_key': public_key,
                'signature': signature,
                'salt': salt  # Store the salt
            }
            flash("User registered successfully! Please sign in.")
            return redirect(url_for('signin'))

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists and verify credentials
        if username in user_data:
            signature = user_data[username]['signature']
            salt = user_data[username]['salt']
            if verify_signature(signature, password, salt):  # Pass the salt
                flash("Sign in successful!")
                return redirect(url_for('home'))
            else:
                flash("Invalid credentials. Please try again.")
        else:
            flash("User not found. Please sign up.")

    return render_template('signin.html')

@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == "__main__":
    app.run(debug=True)
