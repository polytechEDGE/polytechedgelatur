import re
from flask import Flask, jsonify, render_template, request, redirect, send_from_directory, session, url_for, flash
import openai
import os
import json
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
# Add imports for OAuth
import secrets
import urllib.parse
import requests  # Add this for making HTTP requests to OAuth providers

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_super_secret_key")  # Set a unique secret key for session handling
# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polytechedge.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"
app.config['APPLE_CLIENT_ID'] = os.getenv('APPLE_CLIENT_ID')
app.config['APPLE_CLIENT_SECRET'] = os.getenv('APPLE_CLIENT_SECRET')
app.config['APPLE_REDIRECT_URI'] = os.getenv('APPLE_REDIRECT_URI')

CORS(app)  # Enable CORS for all routes
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Social login fields
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    apple_id = db.Column(db.String(100), unique=True, nullable=True)
    is_social_account = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

# Contact model for storing contact form submissions
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Contact {self.name} - {self.subject}>'

# *****************************************************
# 📌 Authentication Routes 
# *****************************************************

# Social Authentication Routes
@app.route('/auth/google')
@app.route('/google_login')
def google_login():
    """
    Google OAuth authentication for login.
    This redirects to Google's OAuth endpoint.
    """
    # Store the next URL if provided
    next_page = request.args.get('next')
    if next_page:
        session['next_url'] = next_page
    
    # Generate state token for CSRF protection
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    session['auth_action'] = 'login'  # Indicate this is for login
    
    # Get Google's configuration from discovery URL
    try:
        google_provider_cfg = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]
        
        # Build the authorization URL
        request_uri = requests.Request(
            'GET',
            authorization_endpoint,
            params={
                'client_id': app.config['GOOGLE_CLIENT_ID'],
                'response_type': 'code',
                'scope': 'openid email profile',
                'redirect_uri': url_for('google_callback', _external=True),
                'state': state
            }
        ).prepare().url
        
        return redirect(request_uri)
    except Exception as e:
        print(f"Error initiating Google OAuth: {str(e)}")
        flash('Error connecting to Google authentication service', 'danger')
        return redirect(url_for('login'))

@app.route('/auth/google/signup')
def google_signup():
    """
    Google OAuth authentication for signup.
    """
    # Store the next URL if provided
    next_page = request.args.get('next')
    if next_page:
        session['next_url'] = next_page
    
    # Generate state token for CSRF protection
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    session['auth_action'] = 'signup'  # Indicate this is for signup
    
    # Get Google's configuration from discovery URL
    try:
        google_provider_cfg = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]
        
        # Build the authorization URL
        request_uri = requests.Request(
            'GET',
            authorization_endpoint,
            params={
                'client_id': app.config['GOOGLE_CLIENT_ID'],
                'response_type': 'code',
                'scope': 'openid email profile',
                'redirect_uri': url_for('google_callback', _external=True),
                'state': state
            }
        ).prepare().url
        
        return redirect(request_uri)
    except Exception as e:
        print(f"Error initiating Google OAuth: {str(e)}")
        flash('Error connecting to Google authentication service', 'danger')
        return redirect(url_for('signup'))

@app.route('/auth/google/callback')
def google_callback():
    """
    Google OAuth callback.
    This handles the response from Google's OAuth service.
    """
    print("Google callback route called")
    
    # Get the URL to redirect to after login
    next_page = session.get('next_url')
    
    # Verify state parameter to prevent CSRF
    state = request.args.get('state')
    stored_state = session.get('oauth_state')
    
    if state is None or state != stored_state:
        print(f"State mismatch: {state} vs {stored_state}")
        flash('Invalid authentication state', 'danger')
        return redirect(url_for('login'))
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        print("No authorization code received")
        flash('Authentication failed', 'danger')
        return redirect(url_for('login'))
    
    try:
        # Get Google provider configuration
        google_provider_cfg = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()
        token_endpoint = google_provider_cfg["token_endpoint"]
        
        # Prepare and send token request
        token_url, headers, body = requests.Request(
            'POST',
            token_endpoint,
            params={
                'client_id': app.config['GOOGLE_CLIENT_ID'],
                'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': url_for('google_callback', _external=True)
            }
        ).prepare()
        
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(app.config['GOOGLE_CLIENT_ID'], app.config['GOOGLE_CLIENT_SECRET'])
        )
        
        # Parse the tokens
        token_data = token_response.json()
        
        # Get user info from ID token
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={'Authorization': f'Bearer {token_data["access_token"]}'}
        )
        
        userinfo = userinfo_response.json()
        
        # Validate response
        if not userinfo.get("email_verified"):
            flash('Email not verified with Google', 'danger')
            return redirect(url_for('login'))
        
        # Create user_info dictionary
        user_info = {
            'id': userinfo["sub"],
            'email': userinfo["email"],
            'name': userinfo.get("name", userinfo["email"].split('@')[0]),
            'picture': userinfo.get("picture")
        }
        
        # Check if this was for login or signup
        auth_action = session.get('auth_action', 'login')
        print(f"Auth action: {auth_action}")
        
        # Process the user
        user = handle_oauth_user('google', user_info, auth_action)
        
        if user:
            # Log the user in
            session['user_id'] = user.id
            session['username'] = user.username
            print(f"User logged in: user_id={user.id}, username={user.username}")
            if auth_action == 'signup':
                flash('Your Google account has been successfully connected and a new account has been created!', 'success')
            else:
                flash('You have successfully logged in with Google!', 'success')
        else:
            print("Failed to get user from handle_oauth_user")
            if auth_action == 'signup':
                flash('Failed to create account. Please try again.', 'danger')
            else:
                flash('Failed to log in. Please try again.', 'danger')
            
    except Exception as e:
        print(f"Error in google_callback: {str(e)}")
        flash(f'An error occurred during authentication: {str(e)}', 'danger')
    
    # Clear the next_url from session since we're using it now
    session.pop('next_url', None)
    session.pop('oauth_state', None)
    
    # Redirect to the original page or home if none was saved
    return redirect(next_page or url_for('home_page'))

@app.route('/auth/apple')
@app.route('/apple_login')
def apple_login():
    """
    Apple Sign In authentication for login.
    This redirects to Apple's OAuth endpoint.
    """
    # Store the next URL if provided
    next_page = request.args.get('next')
    if next_page:
        session['next_url'] = next_page
    
    # Generate state token for CSRF protection
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    session['auth_action'] = 'login'  # Indicate this is for login
    
    # If Apple credentials are not configured, use simulation mode
    if not app.config['APPLE_CLIENT_ID'] or not app.config['APPLE_CLIENT_SECRET']:
        flash('Apple Sign In is currently in simulation mode.', 'info')
        # Directly redirect to callback to simulate successful authentication
        return redirect(url_for('apple_callback'))
        
    try:
        # Build the authorization URL for Apple
        request_uri = requests.Request(
            'GET',
            'https://appleid.apple.com/auth/authorize',
            params={
                'client_id': app.config['APPLE_CLIENT_ID'],
                'response_type': 'code',
                'scope': 'name email',
                'redirect_uri': app.config['APPLE_REDIRECT_URI'] or url_for('apple_callback', _external=True),
                'state': state
            }
        ).prepare().url
        
        return redirect(request_uri)
    except Exception as e:
        print(f"Error initiating Apple OAuth: {str(e)}")
        flash('Error connecting to Apple authentication service', 'danger')
        return redirect(url_for('login'))

@app.route('/auth/apple/signup')
def apple_signup():
    """
    Apple Sign In authentication for signup.
    This redirects to Apple's OAuth endpoint.
    """
    # Store the next URL if provided
    next_page = request.args.get('next')
    if next_page:
        session['next_url'] = next_page
    
    # Generate state token for CSRF protection
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    session['auth_action'] = 'signup'  # Indicate this is for signup
    
    # If Apple credentials are not configured, use simulation mode
    if not app.config['APPLE_CLIENT_ID'] or not app.config['APPLE_CLIENT_SECRET']:
        flash('Apple Sign In is currently in simulation mode.', 'info')
        # Directly redirect to callback to simulate successful authentication
        return redirect(url_for('apple_callback'))
    
    try:
        # Build the authorization URL for Apple
        request_uri = requests.Request(
            'GET',
            'https://appleid.apple.com/auth/authorize',
            params={
                'client_id': app.config['APPLE_CLIENT_ID'],
                'response_type': 'code',
                'scope': 'name email',
                'redirect_uri': app.config['APPLE_REDIRECT_URI'] or url_for('apple_callback', _external=True),
                'state': state
            }
        ).prepare().url
        
        return redirect(request_uri)
    except Exception as e:
        print(f"Error initiating Apple OAuth: {str(e)}")
        flash('Error connecting to Apple authentication service', 'danger')
        return redirect(url_for('signup'))

@app.route('/auth/apple/callback')
def apple_callback():
    """
    Apple Sign In callback.
    This handles the response from Apple's OAuth service.
    """
    print("Apple callback route called")
    
    # Get the URL to redirect to after login
    next_page = session.get('next_url')
    
    # If Apple credentials are not configured, use simulation mode
    if not app.config['APPLE_CLIENT_ID'] or not app.config['APPLE_CLIENT_SECRET']:
        # For this demo, we'll simulate the user info
        user_info = {
            'id': f"apple_{secrets.token_hex(10)}",
            'email': 'demo_user@example.com',
            'name': 'Demo User'
        }
    else:
        # Verify state parameter to prevent CSRF
        state = request.args.get('state')
        stored_state = session.get('oauth_state')
        
        if state is None or state != stored_state:
            print(f"State mismatch: {state} vs {stored_state}")
            flash('Invalid authentication state', 'danger')
            return redirect(url_for('login'))
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            print("No authorization code received")
            flash('Authentication failed', 'danger')
            return redirect(url_for('login'))
        
        try:
            # Exchange code for access token
            token_response = requests.post(
                'https://appleid.apple.com/auth/token',
                data={
                    'client_id': app.config['APPLE_CLIENT_ID'],
                    'client_secret': app.config['APPLE_CLIENT_SECRET'],
                    'code': code,
                    'grant_type': 'authorization_code',
                    'redirect_uri': app.config['APPLE_REDIRECT_URI'] or url_for('apple_callback', _external=True)
                }
            )
            
            token_data = token_response.json()
            
            # Parse ID token to get user info
            # Note: In a real implementation, you would need to verify the JWT signature
            id_token = token_data.get('id_token')
            # TODO: Parse and verify the id_token to get user information
            
            # For now, we'll use placeholder data
            user_info = {
                'id': f"apple_{secrets.token_hex(10)}",  # In reality, this would come from the ID token
                'email': 'user@example.com',  # In reality, this would come from the ID token
                'name': 'Apple User'  # In reality, this would come from the ID token
            }
            
        except Exception as e:
            print(f"Error processing Apple callback: {str(e)}")
            flash(f'An error occurred during authentication: {str(e)}', 'danger')
            return redirect(url_for('login'))
    
    # Check if this was for login or signup
    auth_action = session.get('auth_action', 'login')
    print(f"Auth action: {auth_action}")
    
    # Process the user
    try:
        user = handle_oauth_user('apple', user_info, auth_action)
        
        if user:
            # Log the user in
            session['user_id'] = user.id
            session['username'] = user.username
            print(f"User logged in: user_id={user.id}, username={user.username}")
            if auth_action == 'signup':
                flash('Your Apple account has been successfully connected and a new account has been created!', 'success')
            else:
                flash('You have successfully logged in with Apple!', 'success')
        else:
            print("Failed to get user from handle_oauth_user")
            if auth_action == 'signup':
                flash('Failed to create account. Please try again.', 'danger')
            else:
                flash('Failed to log in. Please try again.', 'danger')
    except Exception as e:
        print(f"Error in apple_callback: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'danger')
    
    # Clear the next_url from session since we're using it now
    session.pop('next_url', None)
    session.pop('oauth_state', None)
    
    # Redirect to the original page or home if none was saved
    return redirect(next_page or url_for('home_page'))

# Function to handle social authentication
def handle_oauth_user(auth_provider, user_info, action='login'):
    """
    Handle OAuth authentication and user creation/login.
    
    Parameters:
    - auth_provider: 'google' or 'apple'
    - user_info: User profile information from the OAuth provider
    - action: 'login' or 'signup'
    
    Returns:
    - User object
    """
    print(f"handle_oauth_user called: provider={auth_provider}, action={action}, user_info={user_info}")
    
    email = user_info.get('email')
    provider_id = user_info.get('id')
    
    if not email or not provider_id:
        print(f"Missing email or provider_id: email={email}, provider_id={provider_id}")
        flash('Email and ID are required for authentication', 'danger')
        return None
    
    try:
        # Check if user already exists by provider ID or email
        user = None
        if auth_provider == 'google':
            user = User.query.filter_by(google_id=provider_id).first()
            print(f"Looking for user with google_id={provider_id}, found: {user}")
        elif auth_provider == 'apple':
            user = User.query.filter_by(apple_id=provider_id).first()
            print(f"Looking for user with apple_id={provider_id}, found: {user}")
        
        if not user:
            # Try finding by email as a fallback
            user = User.query.filter_by(email=email).first()
            print(f"Looking for user with email={email}, found: {user}")
        
        # Handle existing user found
        if user:
            print(f"Existing user found: {user.username}, is_social={user.is_social_account}")
            # If we found the user by email but not by provider ID, update the provider ID
            if (auth_provider == 'google' and not user.google_id) or (auth_provider == 'apple' and not user.apple_id):
                print(f"Updating user's {auth_provider}_id to {provider_id}")
                if auth_provider == 'google':
                    user.google_id = provider_id
                elif auth_provider == 'apple':
                    user.apple_id = provider_id
                
                if not user.is_social_account:
                    user.is_social_account = True
                
                try:
                    db.session.commit()
                    print(f"User updated successfully")
                except Exception as e:
                    db.session.rollback()
                    print(f"Error updating user: {str(e)}")
                    flash(f'Error updating account: {str(e)}', 'danger')
            
            # If this is a signup attempt but user exists
            if action == 'signup':
                flash('An account with this email already exists. Please log in instead.', 'warning')
            
            return user
        
        # Create new user if action is signup or login (auto-signup)
        # Allow auto-signup for login attempts as well to improve user experience
        print(f"No existing user found, creating a new one for {action}")
        
        name = user_info.get('name', '')
        # Generate username from name or email
        if name:
            base_username = name.lower().replace(' ', '_')
        else:
            base_username = email.split('@')[0]
        
        # Ensure username is unique
        username = base_username
        count = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}_{count}"
            count += 1
        
        print(f"Generated username: {username}")
        
        # Create random password
        password = secrets.token_urlsafe(16)
        
        new_user = User(
            username=username,
            email=email,
            is_social_account=True
        )
        
        # Set the provider-specific ID
        if auth_provider == 'google':
            new_user.google_id = provider_id
        elif auth_provider == 'apple':
            new_user.apple_id = provider_id
        
        # Set the password
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            print(f"New user created successfully: {new_user.username}, id={new_user.id}")
            if action == 'login':
                flash('Account automatically created with your social login! Welcome!', 'success')
            return new_user
        except Exception as e:
            db.session.rollback()
            print(f"Error creating user: {str(e)}")
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            return None
    
    except Exception as e:
        print(f"Unexpected error in handle_oauth_user: {str(e)}")
        flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Store the URL the user was trying to access before being redirected to login
    next_page = request.args.get('next') or session.get('next_url')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate input
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return render_template('login.html', next=next_page)
        
        # Check if user exists
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Login successful
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            
            # Clear the next_url from session since we're using it now
            session.pop('next_url', None)
            
            # Redirect to the original page or home if none was saved
            return redirect(next_page or url_for('home_page'))
        else:
            # Login failed
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', next=next_page)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Store the URL the user was trying to access before being redirected to signup
    next_page = request.args.get('next') or session.get('next_url')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Simple validation
        if not username or not email or not password:
            flash('Please fill all required fields', 'danger')
            return render_template('signup.html', next=next_page)
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('signup.html', next=next_page)
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('signup.html', next=next_page)
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('signup.html', next=next_page)
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Automatically log in the user
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            
            flash('Account created successfully! You are now logged in.', 'success')
            
            # Clear the next_url from session since we're using it now
            session.pop('next_url', None)
            
            # Redirect to the original page or home if none was saved
            return redirect(next_page or url_for('home_page'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('signup.html', next=next_page)

@app.route('/logout')
def logout():
    """Log out the current user by clearing their session"""
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('home_page'))

# Function to check if user is logged in
def is_logged_in():
    print(f"Session contents: {session}")
    return 'user_id' in session and session['user_id'] is not None

# Add is_logged_in to all templates
@app.context_processor
def inject_user():
    logged_in = is_logged_in()
    print(f"is_logged_in: {logged_in}, username: {session.get('username')}")
    return dict(is_logged_in=logged_in, username=session.get('username'))

# Debug route to view session
@app.route('/debug_session')
def debug_session():
    session_data = dict(session)
    return jsonify(session_data)

# Debug route to view users in the database
@app.route('/debug_users')
def debug_users():
    try:
        users = User.query.all()
        user_list = []
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'is_social_account': user.is_social_account,
                'google_id': user.google_id,
                'apple_id': user.apple_id
            }
            user_list.append(user_data)
        return jsonify({
            'count': len(user_list),
            'users': user_list
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# Create database tables
with app.app_context():
    db.create_all()

# Load environment variables
load_dotenv()

# **1️⃣ Home Page**
@app.route("/")
def home_page():  # Renamed from "home" to "home_page" to avoid duplication
    return render_template("index.html")


# **2️⃣ Main Page**
@app.route("/guidance")
def guidance_page():
    return render_template("guidance.html")

@app.route("/guidance_main")
def guidance_main_page():
    return render_template("guidance_main.html")

# **3️⃣ Career Recommendations Form**
@app.route("/guidance_courses")
def guidance_courses_page():
    return render_template("guidance_courses.html")

@app.route("/guidance_job")
def guidance_job_page():
    return redirect('/guidance_job2')

@app.route('/job')
def job():
    return redirect('/guidance_job2')



# **4️⃣ Results Page**
@app.route("/guidance_course_results")
def guidance_course_results_page():
    # Check if user is logged in
    if not is_logged_in():
        # Store the current URL in session
        session['next_url'] = request.url
        flash('Please sign up or log in to view course recommendations', 'warning')
        return redirect(url_for('signup'))
    
    # Continue with existing code
    recommendations = session.get("recommendations", None)

    # Check if recommendations exist in session
    if not recommendations:
        recommendations = "<p class='text-center text-danger'>No recommendations available.</p>"
    else:
        # Parse the recommendations if they are in JSON format
        try:
            recommendations = json.loads(recommendations)
        except Exception as e:
            recommendations = "<p class='text-center text-danger'>Error parsing recommendations.</p>"
            print("Error parsing recommendations:", str(e))

    return render_template("guidance_course_results.html", recommendations=recommendations)

@app.route("/recommend", methods=["POST"])
def recommend():
    try:
        data = request.get_json()
        print("\n🔹 Received Data:", data)  # Debugging

        skills = data.get("skills", [])
        branches = data.get("branches", [])
        interests = data.get("interests", [])
        education_type = data.get("education_type", "Courses")

        if not skills and not branches and not interests:
            return jsonify({"success": False, "error": "No input provided"}), 400

        # Ensure OpenAI API Key is set
        if not openai.api_key:
            raise ValueError("OpenAI API key is missing!")

        # Generate AI prompt
        if education_type == "Courses":
            prompt = f"""
            You are a highly experienced **Career Counselor** specializing in **Direct Second-Year (DSY) admissions** after **Polytechnic** in Maharashtra.

            🎓 The student is looking for **PRIVATE INSTITUTES (not colleges) offering courses** after Polytechnic in Maharashtra.

            Based on:
            - **Technical Skills:** {', '.join(skills) if skills else 'Not specified'}
            - **Diploma Branch:** {', '.join(branches) if branches else 'Not specified'}
            - **Interests:** {', '.join(interests) if interests else 'Not specified'}

            📌 **Provide 6 Course Recommendations ONLY from Maharashtra** in the following **JSON format**:
            ```json
            {{
                "recommendations": [
                    {{
                        "course_name": "Full Course Name", <br>
                        "institute": "Institute Name",  <br>
                        "location": "City, Maharashtra",<br>
                        "image_url": "Direct URL to institute/course image",<br>
                        "Official Website": "link of official website",<br>
                        "details": {{
                            "Full Address": "Institute's full address",<br>
                            "Eligibility": "Eligibility Criteria for DSY Admission",<br>
                            "Duration": "Course duration in years",<br>
                            "Fees": "Approximate course fees per year",<br>
                            "Future Scope": "Job & salary prospects",<br>
                            "Industry Tie-ups": "Collaboration with industries for internships or placements"<br>
                        }}
                    }}
                ]
            }}
            ```
            🔸 Ensure all recommendations are **AICTE-approved**.  
            🔸 Provide **direct image URLs** related to the course or institute.
            🔸 Keep the response **strictly in JSON format** with **no extra text**.
            """

        elif education_type == "College":
            prompt = f"""
            You are a highly experienced **Career Counselor** specializing in **Direct Second-Year (DSY) admissions** after **Polytechnic** in Maharashtra.

            🎓 The student is looking for **top colleges** after Polytechnic in Maharashtra.

            Based on:
            - **Technical Skills:** {', '.join(skills) if skills else 'Not specified'}
            - **Diploma Branch:** {', '.join(branches) if branches else 'Not specified'}
            - **Interests:** {', '.join(interests) if interests else 'Not specified'}

            📌 **Provide 6 College Recommendations ONLY from Maharashtra** in the following **JSON format**:
            ```json
            {{
                "recommendations": [
                    {{
                        "college_name": "Full College Name",<br>
                        "location": "City, Maharashtra",<br>
                        "image_url": "Direct URL to college image",<br>
                        "OfficialWebsite": "link of official website",<br>
                        "details": {{
                            "Full Address": "College's full address",<br>
                            "Eligibility": "Eligibility Criteria for DSY Admission",<br>
                            "Streams": "Available courses for DSY students",<br>
                            "Fees & Scholarships": "Approximate fees and scholarships available",<br>
                            "Placement": "Salary packages and placement details",<br>
                            "Industry Tie-ups": "Collaborations with industries for internships"<br>
                        }}
                    }}
                ]
            }}
            ```
            🔸 Ensure all recommendations are **AICTE-approved**.  
            🔸 Provide **direct image URLs** related to the college.  
            🔸 Keep the response **strictly in JSON format** with **no extra text**.
            """
            
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo-0125",
            messages=[{"role": "system", "content": prompt}]
        )

        raw_response = response["choices"][0]["message"]["content"]
        print("\n🔹 OpenAI Raw Response:\n", raw_response)  # Debugging

        # **Extract valid JSON from OpenAI response**
        match = re.search(r"```json\n(.*?)\n```", raw_response, re.DOTALL)
        if match:
            json_str = match.group(1)  # Extract only JSON content
        else:
            json_str = raw_response  # Fallback if markdown formatting is missing

        # Convert JSON string to dictionary
        recommendations = json.loads(json_str)

        # Store recommendations in session
        session["recommendations"] = json.dumps(recommendations)
        session.modified = True

        return jsonify({"success": True, "recommendations": recommendations})

    except Exception as e:
        print("\n❌ Error in API Call:", str(e))
        return jsonify({"success": False, "error": str(e)}), 500



# **6️⃣ Route to Serve Images**
@app.route("/static/images/<path:filename>")
def serve_image(filename):
    return send_from_directory("static/images", filename)



    # ------------------------------------------
    # 📌 job guidance Routes
    # ------------------------------------------

@app.route('/guidance_job_results')
def guidance_job_results():
    # Check if user is logged in
    if not is_logged_in():
        # Store the current URL in session
        session['next_url'] = request.url
        flash('Please sign up or log in to view job recommendations', 'warning')
        return redirect(url_for('signup'))
    
    return redirect('/guidance_job_results.html')

@app.route('/get_roadmap', methods=['POST'])
def get_roadmap():
    try:
        data = request.json
        print("\n🔹 Received Data:", data)  # Debugging

        # Get form data
        education_level = data.get("education_level")
        jobrole = data.get("jobrole")
        skills = data.get("skills", "").split(",") if data.get("skills") else []
        experience = data.get("experience")
        timeline = data.get("timeline")

        if not jobrole:
            return jsonify({"error": "Job role is required"}), 400

        # Generate AI prompt
        prompt = f"""Generate a detailed career roadmap for someone aspiring to be a {jobrole}.

Education Level: {education_level}
Current Skills: {', '.join(skills)}
Experience: {experience}
Timeline: {timeline} years

Please provide a structured roadmap with the following sections:
1. Education Requirements
2. Skill Development
3. Experience Building
4. Career Progression
5. Professional Development
6. Job Search Strategy

Format the response in a clear, structured manner with bullet points and sections."""

        # Ensure OpenAI API Key is set
        if not openai.api_key:
            raise ValueError("OpenAI API key is missing!")

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a career counselor helping students plan their careers."},
                {"role": "user", "content": prompt}
            ]
        )
        
        roadmap = response["choices"][0]["message"]["content"].strip()
        
        # Store roadmap in session for the results page
        session["roadmap"] = roadmap
        session.modified = True
        
        return jsonify({"success": True, "roadmap": roadmap})
    
    except Exception as e:
        print("\n❌ Error in get_roadmap:", str(e))  # Debugging
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/job_results', methods=['GET'])
def job_results():
    # Check if user is logged in
    if not is_logged_in():
        # Store the current URL in session
        session['next_url'] = request.url
        flash('Please sign up or log in to view job recommendations', 'warning')
        return redirect(url_for('signup'))
    
    roadmap = session.get("roadmap", None)
    if not roadmap:
        roadmap = "<p class='text-center text-danger'>No roadmap available. Please generate a new roadmap.</p>"
    return render_template('guidance_job_results.html', roadmap=roadmap)

@app.route('/guidance_job2')
def guidance_job2():
    return render_template('guidance_job2.html')





# ------------------------------------------
# 📌 College Predictor Routes
# ------------------------------------------

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import pandas as pd
import pickle
import os
from utils.prediction import predict_colleges

# Remove duplicate Flask app initialization
# app = Flask(__name__)
# app.secret_key = 'your_secret_key'  # Replace with a secure key

# Register template filters
@app.template_filter('ge')
def greater_than_equal(value, other):
    return value >= other

# Check if model and data files exist
def load_model_and_data():
    model_path = os.path.join('models', 'college_predictor_model.pkl')
    encoder_path = os.path.join('models', 'feature_encoder.pkl')
    data_path = os.path.join('data', 'cleaned_cutoff_data.csv')
    
    if not os.path.exists(model_path) or not os.path.exists(encoder_path):
        print("Model or encoder file not found. Please run train_model.py first.")
        return None, None, None
    
    if not os.path.exists(data_path):
        print("Data file not found. Please run process_pdfs.py first.")
        return None, None, None
    
    # Load the model, encoder, and cutoff data
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    
    with open(encoder_path, 'rb') as f:
        encoder = pickle.load(f)
    
    cutoff_data = pd.read_csv(data_path)
    
    return model, encoder, cutoff_data

model, encoder, cutoff_data = load_model_and_data()

@app.route('/predictor')
def predictor():
    return render_template('predictor.html')

@app.route('/step1', methods=['GET', 'POST'])
def step1():
    if request.method == 'POST':
        # Get user marks
        marks = float(request.form.get('marks', 0))
        session['user_marks'] = marks
        return redirect(url_for('step2'))
    
    return render_template('step1.html')

@app.route('/step2', methods=['GET', 'POST'])
def step2():
    if request.method == 'POST':
        # Check if model is loaded
        if model is None or encoder is None or cutoff_data is None:
            return render_template('error.html', 
                                  message="Model or data files not found. Please process your PDF files first.")
        
        # Get user preferences
        college_type = request.form.get('college_type')
        location = request.form.get('location')
        branch = request.form.get('branch')
        category = request.form.get('category')
        
        # Get user marks from session
        marks = session.get('user_marks', 0)
        
        # Create user input dictionary
        user_input = {
            'marks': marks,
            'category': category,
            'branch': branch,
            'college_type': college_type,
            'location': location
        }
        
        # Get college predictions
        recommendations = predict_colleges(user_input, model, encoder, cutoff_data)
        
        # Store recommendations in session
        session['recommendations'] = recommendations.to_dict('records')
        
        return redirect(url_for('predictor_results'))
    
    return render_template('step2.html')

@app.route('/predictor_results')
def predictor_results():
    # Check if user is logged in
    if not is_logged_in():
        # Store the current URL in session
        session['next_url'] = request.url
        flash('Please sign up or log in to view college predictions', 'warning')
        return redirect(url_for('signup'))
    
    recommendations = session.get('recommendations', [])
    return render_template('pre_result.html', colleges=recommendations)



    # ------------------------------------------
    # 📌 Polytech Portal 
    # ------------------------------------------




# Serve static files
@app.route('/<path:filename>')
def serve_static(filename):
    if filename.endswith(('.jpg', '.jpeg', '.png', '.svg', '.webp')):
        return send_from_directory('.', filename)
    return render_template(filename)

# Home route
@app.route('/portal')
def portal():
    return render_template('portal.html')

# Scheme routes
@app.route('/K & I scheme')
def K_I_scheme():
    return render_template('K & I scheme.html')

@app.route('/k-scheme')
def k_scheme():
    return render_template('K-SCHEME.html')

# Scheme routes
@app.route('/i-scheme')
def i_scheme():
    return render_template('I-SCHEME.html')

# Civil Engineering routes
@app.route('/ce-i-scheme')
def ce_i_scheme():
    return render_template('CE (I-SCHEME) Semesterpage.html')

@app.route('/ce-k-scheme')
def ce_k_scheme():
    return render_template('CE (K-SCHEME) Semesterpage.html')

@app.route('/ce-sem1-i-scheme')
def ce_sem1_i_scheme():
    return render_template('CE sem1(i-scheme).html')

@app.route('/ce-sem1-k-scheme')
def ce_sem1_k_scheme():
    return render_template('CE sem1(k-scheme).html')

@app.route('/ce-sem2-i-scheme')
def ce_sem2_i_scheme():
    return render_template('CE sem2(i-scheme).html')

@app.route('/ce-sem2-k-scheme')
def ce_sem2_k_scheme():
    return render_template('CE sem2(k-scheme).html')

@app.route('/ce-sem3-i-scheme')
def ce_sem3_i_scheme():
    return render_template('CE sem3(i-scheme).html')

@app.route('/ce-sem3-k-scheme')
def ce_sem3_k_scheme():
    return render_template('CE sem3(k-scheme).html')

@app.route('/ce-sem4-i-scheme')
def ce_sem4_i_scheme():
    return render_template('CE sem4(i-scheme).html')

@app.route('/ce-sem4-k-scheme')
def ce_sem4_k_scheme():
    return render_template('CE sem4(k-scheme).html')

@app.route('/ce-sem5-i-scheme')
def ce_sem5_i_scheme():
    return render_template('CE sem5(i-scheme).html')

@app.route('/ce-sem6-i-scheme')
def ce_sem6_i_scheme():
    return render_template('CE sem6(i-scheme).html')

# Computer Engineering routes
@app.route('/co-i-scheme')
def co_i_scheme():
    return render_template('CO (I-SCHEME) Semesterpage.html')

@app.route('/co-k-scheme')
def co_k_scheme():
    return render_template('CO (K-SCHEME) Semesterpage.html')

@app.route('/co-sem1-i-scheme')
def co_sem1_i_scheme():
    return render_template('CO sem1(i-scheme).html')

@app.route('/co-sem1-k-scheme')
def co_sem1_k_scheme():
    return render_template('CO sem1(k-scheme).html')

@app.route('/co-sem2-i-scheme')
def co_sem2_i_scheme():
    return render_template('CO sem2(i-scheme).html')

@app.route('/co-sem2-k-scheme')
def co_sem2_k_scheme():
    return render_template('CO sem2(k-scheme).html')

@app.route('/co-sem3-i-scheme')
def co_sem3_i_scheme():
    return render_template('CO sem3(i-scheme).html')

@app.route('/co-sem3-k-scheme')
def co_sem3_k_scheme():
    return render_template('CO sem3(k-scheme).html')

@app.route('/co-sem4-i-scheme')
def co_sem4_i_scheme():
    return render_template('CO sem4(i-scheme).html')

@app.route('/co-sem4-k-scheme')
def co_sem4_k_scheme():
    return render_template('CO sem4(k-scheme).html')

@app.route('/co-sem5-i-scheme')
def co_sem5_i_scheme():
    return render_template('CO sem5(i-scheme).html')

@app.route('/co-sem6-i-scheme')
def co_sem6_i_scheme():
    return render_template('CO sem6(i-scheme).html')

# Electronics and Telecommunication routes
@app.route('/etc-i-scheme')
def etc_i_scheme():
    return render_template('E&TC (I-SCHEME) Semesterpage.html')

@app.route('/etc-sem1-i-scheme')
def etc_sem1_i_scheme():
    return render_template('E&TC sem1(i-scheme).html')

@app.route('/etc-sem2-i-scheme')
def etc_sem2_i_scheme():
    return render_template('E&TC sem2(i-scheme).html')

@app.route('/etc-sem3-i-scheme')
def etc_sem3_i_scheme():
    return render_template('E&TC sem3(i-sceme).html')

@app.route('/etc-sem4-i-scheme')
def etc_sem4_i_scheme():
    return render_template('E&TC sem4(i-scheme).html')

@app.route('/etc-sem5-i-scheme')
def etc_sem5_i_scheme():
    return render_template('E&TC sem5(i-scheme).html')

@app.route('/etc-sem6-i-scheme')
def etc_sem6_i_scheme():
    return render_template('E&TC sem6(i-scheme).html')

@app.route('/etc-k-scheme')
def etc_k_scheme():
    return render_template('E&TC (K-SCHEME) Semesterpage.html')

# Electrical Engineering routes
@app.route('/ee-i-scheme')
def ee_i_scheme():
    return render_template('EE (I-SCHEME) Semesterpage.html')

@app.route('/ee-k-scheme')
def ee_k_scheme():
    return render_template('EE (K-SCHEME) Semesterpage.html')

@app.route('/ee-sem1-i-scheme')
def ee_sem1_i_scheme():
    return render_template('EE sem1(i-scheme).html')

@app.route('/ee-sem1-k-scheme')
def ee_sem1_k_scheme():
    return render_template('EE sem1(k-scheme).html')

@app.route('/ee-sem2-i-scheme')
def ee_sem2_i_scheme():
    return render_template('EE sem2(i-scheme).html')

@app.route('/ee-sem2-k-scheme')
def ee_sem2_k_scheme():
    return render_template('EE sem2(k-scheme).html')

@app.route('/ee-sem3-i-scheme')
def ee_sem3_i_scheme():
    return render_template('EE sem3(i-scheme).html')

@app.route('/ee-sem3-k-scheme')
def ee_sem3_k_scheme():
    return render_template('EE sem3(k-scheme).html')

@app.route('/ee-sem4-i-scheme')
def ee_sem4_i_scheme():
    return render_template('EE sem4(i-scheme).html')

@app.route('/ee-sem4-k-scheme')
def ee_sem4_k_scheme():
    return render_template('EE sem4(k-scheme).html')

@app.route('/ee-sem5-i-scheme')
def ee_sem5_i_scheme():
    return render_template('EE sem5(i-scheme).html')

@app.route('/ee-sem6-i-scheme')
def ee_sem6_i_scheme():
    return render_template('EE sem6(i-scheme).html')

# Electronics Engineering routes
@app.route('/ex-k-scheme')
def ex_k_scheme():
    return render_template('EX (K-SCHEME) Semesterpage.HTML')

@app.route('/ex-i-scheme')
def ex_i_scheme():
    # Since the I-SCHEME file doesn't exist, temporarily redirect to K-SCHEME version
    return redirect(url_for('ex_k_scheme'))

@app.route('/ex-sem1-k-scheme')
def ex_sem1_k_scheme():
    return render_template('EX sem1(k-scheme).html')

@app.route('/ex-sem2-k-scheme')
def ex_sem2_k_scheme():
    return render_template('EX sem2(k-scheme).html')

@app.route('/ex-sem3-k-scheme')
def ex_sem3_k_scheme():
    return render_template('EX sem3(k-scheme).html')

@app.route('/ex-sem4-k-scheme')
def ex_sem4_k_scheme():
    return render_template('EX sem4(k-scheme).html')

# Information Technology routes
@app.route('/it-i-scheme')
def it_i_scheme():
    return render_template('IT (I-SCHEME) Semesterpage.html')

@app.route('/it-k-scheme')
def it_k_scheme():
    return render_template('IT (K-SCHEME) Semster.html')

@app.route('/it-sem1-i-scheme')
def it_sem1_i_scheme():
    return render_template('IT sem1(i-scheme).html')

@app.route('/it-sem1-k-scheme')
def it_sem1_k_scheme():
    return render_template('IT sem1(k-scheme).html')

@app.route('/it-sem2-i-scheme')
def it_sem2_i_scheme():
    return render_template('IT sem2(i-scheme).html')

@app.route('/it-sem2-k-scheme')
def it_sem2_k_scheme():
    return render_template('IT sem2(k-scheme).html')

@app.route('/it-sem3-i-scheme')
def it_sem3_i_scheme():
    return render_template('IT sem3(i-scheme).html')

@app.route('/it-sem3-k-scheme')
def it_sem3_k_scheme():
    return render_template('IT sem3(k-scheme).html')

@app.route('/it-sem4-i-scheme')
def it_sem4_i_scheme():
    return render_template('IT sem4(i-scheme).html')

@app.route('/it-sem4-k-scheme')
def it_sem4_k_scheme():
    return render_template('IT sem4(k-scheme).html')

@app.route('/it-sem5-i-scheme')
def it_sem5_i_scheme():
    return render_template('IT sem5(i-scheme).html')

@app.route('/it-sem6-i-scheme')
def it_sem6_i_scheme():
    return render_template('IT sem6(i-scheme).html')

# Mechanical Engineering routes
@app.route('/me-i-scheme')
def me_i_scheme():
    return render_template('ME (I-SCHEME) Semester.html')

@app.route('/me-k-scheme')
def me_k_scheme():
    return render_template('ME (K-SCHEME) Semster.html')

@app.route('/me-sem1-k-scheme')
def me_sem1_k_scheme():
    return render_template('ME sem1(k-scheme).html')

@app.route('/me-sem1-i-scheme')
def me_sem1_i_scheme():
    return render_template('ME sem1(i-scheme).html')

@app.route('/me-sem2-k-scheme')
def me_sem2_k_scheme():
    return render_template('ME sem2(k-scheme).html')

@app.route('/me-sem2-i-scheme')
def me_sem2_i_scheme():
    return render_template('ME sem2(i-scheme).html')

@app.route('/me-sem3-k-scheme')
def me_sem3_k_scheme():
    return render_template('ME sem3(k-scheme).html')

@app.route('/me-sem3-i-scheme')
def me_sem3_i_scheme():
    return render_template('ME sem3(i-scheme).html')

@app.route('/me-sem4-k-scheme')
def me_sem4_k_scheme():
    return render_template('ME sem4(k-scheme).html')

@app.route('/me-sem4-i-scheme')
def me_sem4_i_scheme():
    return render_template('ME sem4(i-scheme).html')

@app.route('/me-sem5-i-scheme')
def me_sem5_i_scheme():
    return render_template('ME sem5(i-scheme).html')

@app.route('/me-sem6-i-scheme')
def me_sem6_i_scheme():
    return render_template('ME sem6(i-scheme).html')

@app.route('/etc-ischeme')
def etc_ischeme_page():
    return render_template('E&TC (I-SCHEME) Semesterpage.html')

@app.route('/etc-sem3-ischeme')
def etc_sem3_ischeme():
    return render_template('E&TC sem3(i-scheme).html')

@app.route('/etc-sem4-ischeme')
def etc_sem4_ischeme():
    return render_template('E&TC sem4(i-scheme).html')

@app.route('/etc-sem5-ischeme')
def etc_sem5_ischeme():
    return render_template('E&TC sem5(i-scheme).html')

@app.route('/etc-sem6-ischeme')
def etc_sem6_ischeme():
    return render_template('E&TC sem6(i-scheme).html')

@app.route('/etc-kscheme')
def etc_kscheme():
    return render_template('E&TC (K-SCHEME) Semesterpage.html')

# *****************************************************
# 📌 Admin Routes 
# *****************************************************

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Basic admin authentication
    if request.method == 'POST':
        admin_password = request.form.get('password')
        # Simple admin password check - in production, use a more secure method
        if admin_password == 'admin123':
            session['is_admin'] = True
            flash('Admin login successful', 'success')
        else:
            flash('Invalid admin password', 'danger')
    
    # If not authenticated, show login
    if not session.get('is_admin'):
        return render_template('admin_login.html')
    
    # If authenticated, show users
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Logged out of admin panel', 'info')
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if not session.get('is_admin'):
        flash('Admin access required', 'danger')
        return redirect(url_for('admin'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/reset_password', methods=['POST'])
def reset_user_password():
    if not session.get('is_admin'):
        flash('Admin access required', 'danger')
        return redirect(url_for('admin'))
    
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not user_id or not new_password or not confirm_password:
        flash('All fields are required', 'danger')
        return redirect(url_for('admin'))
    
    if new_password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('admin'))
    
    user = User.query.get_or_404(user_id)
    user.set_password(new_password)
    db.session.commit()
    
    flash(f'Password for {user.username} has been reset successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/contacts')
def admin_contacts():
    """Admin route to view contact form submissions"""
    # Verify admin is logged in
    if not session.get('is_admin'):
        flash('Admin access required', 'danger')
        return redirect(url_for('admin'))
    
    # Get all contact submissions, newest first
    contacts = Contact.query.order_by(Contact.created_at.desc()).all()
    return render_template('admin_contacts.html', contacts=contacts)

@app.route('/admin/delete_contact/<int:contact_id>')
def delete_contact(contact_id):
    """Admin route to delete a contact form submission"""
    if not session.get('is_admin'):
        flash('Admin access required', 'danger')
        return redirect(url_for('admin'))
    
    contact = Contact.query.get_or_404(contact_id)
    db.session.delete(contact)
    db.session.commit()
    
    flash(f'Contact from {contact.name} deleted successfully', 'success')
    return redirect(url_for('admin_contacts'))

# *****************************************************
# 📌 User Profile Routes 
# *****************************************************

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Check if user is logged in
    if not is_logged_in():
        flash('Please log in to view your profile', 'warning')
        return redirect(url_for('login'))
    
    # Get the current user
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('logout'))
    
    # Handle form submission (profile update)
    if request.method == 'POST':
        # Get form data
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Check if username already exists (if changed)
        if new_username != user.username and User.query.filter_by(username=new_username).first():
            flash('Username already exists', 'danger')
        # Check if email already exists (if changed)
        elif new_email != user.email and User.query.filter_by(email=new_email).first():
            flash('Email already exists', 'danger')
        else:
            # Update username and email
            user.username = new_username
            user.email = new_email
            
            # Check if password change is requested
            if current_password and new_password:
                # Verify current password
                if user.check_password(current_password):
                    if new_password == confirm_password:
                        user.set_password(new_password)
                        flash('Password updated successfully', 'success')
                    else:
                        flash('New passwords do not match', 'danger')
                else:
                    flash('Current password is incorrect', 'danger')
            
            try:
                db.session.commit()
                # Update session username
                session['username'] = new_username
                flash('Profile updated successfully', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('profile.html', user=user)

# *****************************************************
# 📌 Static Page Routes
# *****************************************************

@app.route('/about')
def about():
    """Route for the About Us page"""
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Route for the Contact Us page with form handling"""
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        category = request.form.get('category')
        message = request.form.get('message')
        
        # Validate input
        if not all([name, email, subject, category, message]):
            flash('Please fill all required fields', 'danger')
            return render_template('contact.html')
        
        # Create new contact entry
        new_contact = Contact(
            name=name,
            email=email,
            subject=subject,
            category=category,
            message=message
        )
        
        try:
            # Save to database
            db.session.add(new_contact)
            db.session.commit()
            
            # Send notification to admin (in a real app)
            # send_contact_notification(new_contact)
            
            flash('Thank you for your message! We will get back to you soon.', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('contact.html')

if __name__ == '__main__':
    # Use environment variables for host and port if available
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host=host, port=port, debug=debug)
