import os
from flask import Flask, render_template, request, redirect, url_for, flash
from auth_utils import generate_signature, verify_signature
from login import authenticate_user

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Store user credentials
user_data = {}

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists and update or register
        if username in user_data:
            public_key, signature = generate_signature(password)
            user_data[username]['signature'] = signature
            flash("User already exists. Signature generated.")
        else:
            public_key, signature = generate_signature(password)
            user_data[username] = {
                'public_key': public_key,
                'signature': signature
            }
            flash("User registered successfully!")

        return redirect(url_for('home'))

    return render_template('index.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists
        if username in user_data:
            public_key = user_data[username]['public_key']
            # Verify the password with the signature and public key
            if verify_signature(password, public_key):
                flash("Signature verification successful.")
            else:
                flash("Signature verification failed.")
        else:
            flash("User not found.")
        
        return redirect(url_for('verify'))

    return render_template('verify.html')

if __name__ == "__main__":
    app.run(debug=True)
