from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
from cryptography.fernet import Fernet
from models import db, User
from utils import check_password_strength, send_email
from oauth import init_oauth
from dotenv import load_dotenv
from encryption import encrypt_file
from cryptography.hazmat.primitives import serialization
from decryption import handle_decryption_routes

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = True  # Only for development

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize OAuth
init_oauth(app)

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Register decryption routes
handle_decryption_routes(app)

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(int(user_id))
    return None

# Create database tables
with app.app_context():
    db.create_all()

# Decryption function
def decrypt_file(file, key_file):
    key = key_file.read()
    fernet = Fernet(key)
    encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + file.filename)
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    return decrypted_file_path

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Store next parameter in session
    if request.args.get('next'):
        session['next'] = request.args.get('next')
    
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.is_locked:
            flash('Your account is locked. Please check your email for details.', 'warning')
            return redirect(url_for('login'))
        
        if user and user.check_password(password):
            # Set session permanent to use the PERMANENT_SESSION_LIFETIME
            session.permanent = True
            login_user(user, remember=True)
            user.reset_login_attempts()
            flash('Logged in successfully!', 'success')
            # Get next URL from session or default to index
            next_url = session.pop('next', url_for('index'))
            # Ensure the next page is relative
            if next_url and next_url.startswith('/'):
                return redirect(next_url)
            return redirect(url_for('index'))
        
        if user:
            user.increment_login_attempts()
            if user.is_locked:
                send_email(user.email, 'Account Locked', 
                          'Your account has been locked due to multiple failed login attempts.')
                flash('Your account is now locked. Please check your email for details.', 'danger')
            else:
                flash(f'Invalid password. {4 - user.login_attempts} attempts remaining.', 'danger')
        else:
            flash('Email not found. Please register first.', 'warning')
        
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password.', 'warning')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please login.', 'warning')
            return redirect(url_for('login'))
        
        # Check password strength
        is_strong, message = check_password_strength(password)
        if not is_strong:
            flash(message, 'warning')
            return redirect(url_for('signup'))
        
        try:
            # Create new user
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            send_email(email, 'Welcome to Our Platform', 
                      'Thank you for registering! Your account has been created successfully.')
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/password_checker', methods=['GET', 'POST'])
@login_required
def password_checker():
    strength = None
    if request.method == 'POST':
        password = request.form['password']
        is_strong, message = check_password_strength(password)
        strength = message
    return render_template('password_checker.html', strength=strength)

@app.route('/encryption', methods=['GET', 'POST'])
@login_required
def encryption():
    if request.method == 'POST':
        file = request.files['file']
        algorithm = request.form['algorithm']
        encrypted_file_path, key = encrypt_file(file, algorithm, app.config['UPLOAD_FOLDER'])
        
        # Prepare response data
        response_data = {
            'key': key,
            'file_url': url_for('serve_uploads', filename=os.path.basename(encrypted_file_path))
        }
        
        return response_data  # Return JSON response
    
    return render_template('encryption.html')

@app.route('/awareness')
@login_required
def awareness():
    return render_template('awareness.html')

@app.route('/dos_donts')
@login_required
def dos_donts():
    return render_template('dos_donts.html')

@app.route('/attacks')
@login_required
def attacks():
    return render_template('attacks.html')

@app.route('/ppt')
@login_required
def ppt():
    return render_template('ppt.html')

@app.route('/phishing-protection')
@login_required
def phishing_protection():
    return render_template('phishing_protection.html')

@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)