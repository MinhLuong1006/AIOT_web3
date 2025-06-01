import os
from werkzeug.security import check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import firebase_admin
from firebase_admin import credentials, db
import time
from flask_cors import CORS
import bcrypt
import threading
import re
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
MOCK_PURCHASE_HISTORY = [
    {
        'id': str(uuid.uuid4()),
        'date': '2024-05-30',
        'item': 'Wireless Bluetooth Headphones',
        'category': 'Electronics',
        'amount': 89.99,
        'status': 'Delivered'
    },
    {
        'id': str(uuid.uuid4()),
        'date': '2024-05-28',
        'item': 'Premium Coffee Beans (2kg)',
        'category': 'Food & Beverages',
        'amount': 24.50,
        'status': 'Delivered'
    },
    {
        'id': str(uuid.uuid4()),
        'date': '2024-05-25',
        'item': 'Fitness Tracker Watch',
        'category': 'Health & Fitness',
        'amount': 149.99,
        'status': 'Processing'
    },
    {
        'id': str(uuid.uuid4()),
        'date': '2024-05-22',
        'item': 'Organic Cotton T-Shirt',
        'category': 'Clothing',
        'amount': 29.99,
        'status': 'Delivered'
    },
    {
        'id': str(uuid.uuid4()),
        'date': '2024-05-20',
        'item': 'Kitchen Knife Set',
        'category': 'Home & Kitchen',
        'amount': 79.95,
        'status': 'Delivered'
    }
]
app = Flask(__name__)

app.config['SECRET_KEY'] = 'iotproject'
CORS(app)  # Enable CORS for all routes
# Initialize Firebase Admin SDK
cred = credentials.Certificate("auto-checkout-b3ea1-firebase-adminsdk-fbsvc-cc9ec9d04b.json")
firebase_admin.initialize_app(cred, {
    "databaseURL": "https://auto-checkout-b3ea1-default-rtdb.asia-southeast1.firebasedatabase.app/"
})
# Flask-Mail configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='minhluong10062006@gmail.com',
    MAIL_PASSWORD='pclg gmfq phec uits',
    MAIL_DEFAULT_SENDER='minhluong10062006@gmail.com',
    MAIL_MAX_EMAILS=None,
    MAIL_SUPPRESS_SEND=False,  # Set to True to suppress sending in development
    MAIL_ASCII_ATTACHMENTS=False
)

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # Token serializer



def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember')

        if not email or not password:
            flash('Please enter both email and password!', 'error')
            return render_template('login.html')

        try:
            # Get the specific user using the sanitized email
            sanitized_email = sanitize_email(email)
            user_ref = db.reference(f'users/{sanitized_email}')
            user_data = user_ref.get()

            if user_data and check_password_hash(user_data['password'], password):
                # Login success
                session['user_id'] = sanitized_email
                session['username'] = user_data['username']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))  # Change this to your actual home/dashboard route
            else:
                flash('Invalid email or password.', 'error')

        except Exception as e:
            flash(f'Login error: {str(e)}', 'error')
            
    return render_template('login.html')

def sanitize_email(email):
    # Replace '.' with ',' or another safe character (',' is readable and allowed)
    return email.replace('.', ',')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic validation
        if not all([email, username, password, confirm_password]):
            flash('Please fill in all fields!', 'error')
        elif not validate_email(email):
            flash('Please enter a valid email address!', 'error')
        elif len(username) < 3:
            flash('Username must be at least 3 characters long!', 'error')
        elif password != confirm_password:
            flash('Passwords do not match!', 'error')
        else:
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
            else:
                try:
                    sanitized_email = sanitize_email(email)
                    user_ref = db.reference(f'users/{sanitized_email}')

                    # Check if user already exists
                    if user_ref.get():
                        flash('An account with this email already exists.', 'error')
                        return render_template('signup.html')

                    # Save user data
                    hashed_password = generate_password_hash(password)
                    user_ref.set({
                        'email': email,
                        'username': username,
                        'password': hashed_password,
                        'balance': 100
                    })

                    flash('Account created successfully! You can now log in.', 'success')
                    return redirect(url_for('login'))

                except Exception as e:
                    flash(f'Error saving to Firebase: {e}', 'error')
    
    return render_template('signup.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']

        # Validate email format
        if not validate_email(email):
            flash('Please enter a valid email address!', 'error')
            return render_template('reset_password.html')

        # Check if email exists in Firebase using sanitized email
        sanitized_email = sanitize_email(email)
        user_ref = db.reference(f'users/{sanitized_email}')
        user_data = user_ref.get()

        if not user_data:
            flash('Email not found. Please try again.', 'error')
            return render_template('reset_password.html')

        # Generate password reset token
        token = s.dumps(email, salt='password-reset')

        # Create reset URL
        reset_url = url_for('reset_with_token', token=token, _external=True)

        # Send email
        try:
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            mail.send(msg)
            flash('Password reset link sent to your email.', 'success')
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'error')

        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = s.loads(token, salt="password-reset", max_age=3600)  # Valid for 1 hour
    except SignatureExpired:
        flash("The token is expired! Please request a new one.", 'error')
        return redirect(url_for('reset_password'))
    except:
        flash("Invalid token!", 'error')
        return redirect(url_for('reset_password'))

    # Check if user exists using sanitized email
    sanitized_email = sanitize_email(email)
    user_ref = db.reference(f'users/{sanitized_email}')
    user_data = user_ref.get()

    if not user_data:
        flash("Invalid token!", 'error')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match, please try again.", 'error')
            return render_template("reset_with_token.html", token=token)

        # Validate password strength
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template("reset_with_token.html", token=token)

        # Update password in Firebase using Werkzeug's generate_password_hash
        try:
            hashed_password = generate_password_hash(new_password)
            user_ref.update({
                'password': hashed_password
            })
            
            flash('Password reset successfully! You can now log in with your new password.', 'success')
            return redirect(url_for("login"))
            
        except Exception as e:
            flash(f"Error updating password: {str(e)}", 'error')
            return render_template("reset_with_token.html", token=token)

    return render_template("reset_with_token.html", token=token)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_ref = db.reference(f'users/{user_id}')
        user_data = user_ref.get()

        if not user_data:
            flash("User data not found.", "error")
            return redirect(url_for('login'))

        balance = user_data.get('balance', 0)
        username = user_data.get('username', 'User')

        return render_template('dashboard.html', balance=balance, username=username)

    except Exception as e:
        flash(f"Error loading dashboard: {e}", "error")
        return redirect(url_for('login'))


@app.route('/purchase-history')
def purchase_history():
    if 'user_id' not in session:
        flash('Please log in to access your account.', 'error')
        return redirect(url_for('login'))
    
    return render_template('purchase_history.html', 
                         purchases=MOCK_PURCHASE_HISTORY,
                         username=session.get('username', 'User'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))
    
if __name__ == '__main__':
    app.run(debug=True)