from flask import Flask, render_template, jsonify, request, g, redirect, url_for, session, flash
from functools import wraps
import os
import json
import random
import string
import psycopg2
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import supabase_client as sb
from supabase_client import get_supabase_client
import uuid
import datetime

# Load environment variables
load_dotenv()

# Helper function for getting auth users
def get_auth_users():
    """Helper function to get users from Supabase Auth with proper error handling"""
    try:
        auth_users_response = sb.supabase.auth.admin.list_users()
        
        # Print the response for debugging
        print(f"Auth users response type: {type(auth_users_response)}")
        
        # Try different ways to access the users based on the response structure
        if hasattr(auth_users_response, 'users'):
            return auth_users_response.users
        elif isinstance(auth_users_response, list):
            return auth_users_response
        elif hasattr(auth_users_response, 'data'):
            if isinstance(auth_users_response.data, list):
                return auth_users_response.data
            else:
                print(f"auth_users_response.data is not a list: {auth_users_response.data}")
                return []
        else:
            print(f"Could not determine the structure of auth_users_response: {auth_users_response}")
            return []
    except Exception as e:
        print(f"Error getting auth users: {e}")
        import traceback
        traceback.print_exc()
        return []

# Create Flask app
app = Flask(__name__, static_folder='static')

# Generate and set secret key
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_for_testing')
print(f"Current secret key: {app.secret_key}")

# Database configuration - use environment variable
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'postgresql://hr_data_xddp_user:nK9wVkeJqxdxMcZ59f9662MgNkVw1Ra0@dpg-curorp8fnakc739lj060-a.frankfurt-postgres.render.com/hr_data_xddp?sslmode=require')

# Legacy database functions - will be replaced with Supabase
def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(app.config['DATABASE_URL'])
        g.cursor = g.db.cursor(cursor_factory=DictCursor)
    return g.db, g.cursor

def close_db(e=None):
    cursor = g.pop('cursor', None)
    if cursor is not None:
        cursor.close()
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    try:
        db, cursor = get_db()
        
        # Check if items table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'items'
            );
        """)
        items_table_exists = cursor.fetchone()[0]
        
        # Check if users table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'users'
            );
        """)
        users_table_exists = cursor.fetchone()[0]

        print(f"Items table exists: {items_table_exists}")
        print(f"Users table exists: {users_table_exists}")

        # Always execute the schema.sql to ensure all tables are created
        with open('schema.sql', 'r') as f:
            print("Initializing database with schema.sql...")
            sql_script = f.read()
            cursor.execute(sql_script)
            db.commit()
            print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")
        if 'db' in locals():
            db.rollback()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
            
        # If user is already an admin, proceed
        if session.get('role') == 'admin':
            return f(*args, **kwargs)
            
        try:
            # Check if there are any admin users in the system
            admin_count = sb.count_users_by_role('admin')
            
            # If there are no admins, promote the current user to admin
            if admin_count == 0:
                sb.update_user(session.get('user_id'), {'role': 'admin'})
                
                # Update session
                session['role'] = 'admin'
                
                flash('You have been granted administrator privileges because there were no administrators in the system.', 'info')
                return f(*args, **kwargs)
        except Exception as e:
            print(f"Error checking admin count: {e}")
        
        flash('You need administrator privileges to access this page.', 'error')
        return redirect(url_for('home', category='anstalld'))
    return decorated_function

@app.route("/")
def index():
    if session.get('logged_in'):
        return redirect(url_for('home', category='anstalld'))
    
    try:
        # Check if there are any users in the database
        print("Checking for users in the database...")
        users = sb.get_all_users()
        print(f"Users found in users table: {users}")
        
        # Also check Supabase Auth
        auth_users = get_auth_users()
        print(f"Users found in Supabase Auth: {len(auth_users)}")
        
        user_count = len(users)
        auth_user_count = len(auth_users)
        
        print(f"User count in users table: {user_count}")
        print(f"User count in Supabase Auth: {auth_user_count}")
        
        # Only redirect to register if both are empty
        if user_count == 0 and auth_user_count == 0:
            print("No users found, redirecting to register page")
            flash('Inga användare finns i systemet. Registrera dig för att bli den första administratören.', 'info')
            return redirect(url_for('register'))
        elif user_count == 0 and auth_user_count > 0:
            # Users exist in Auth but not in users table - this is a problem
            print("Users exist in Auth but not in users table")
            flash('Det finns användare i autentiseringssystemet men inte i användartabellen. Kontakta administratören.', 'warning')
    except Exception as e:
        print(f"Error checking user count: {e}")
        # Continue to login page even if there's an error
    
    print("Rendering login page")
    return render_template("login.html")

@app.route("/login")
def login_page():
    return redirect(url_for('index'))

@app.route("/register")
def register():
    if session.get('logged_in'):
        return redirect(url_for('home', category='anstalld'))
    
    return render_template("register.html")

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    full_name = request.form.get('full_name', '')
    
    print(f"Signup attempt: {username}, {email}")
    
    # Input validation
    if not username or not email or not password:
        flash('All fields are required')
        return redirect(url_for('register'))
    
    # Password validation
    if len(password) < 6:
        flash('Password must be at least 6 characters long')
        return redirect(url_for('register'))
    
    try:
        supabase = get_supabase_client()
        
        # Check if email exists in Supabase Auth
        auth_users = sb.get_auth_users()
        for user in auth_users:
            if hasattr(user, 'email') and user.email == email:
                print(f"Email already exists in Auth: {email}")
                flash('Email already exists')
                return redirect(url_for('register'))
            elif isinstance(user, dict) and user.get('email') == email:
                print(f"Email already exists in Auth: {email}")
                flash('Email already exists')
                return redirect(url_for('register'))
        
        # Check if username exists in users table
        username_check = supabase.table("users").select("username").eq("username", username).execute()
        if username_check.data:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Check if this is the first user (to make them admin)
        user_count = len(sb.get_all_users())
        role = "admin" if user_count == 0 else "user"
        
        # Create auth user with admin API
        auth_response = supabase.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": True,
            "user_metadata": {
                "username": username,
                "full_name": full_name,
                "role": role
            }
        })
        
        if auth_response.user:
            user_id = auth_response.user.id
            
            # Store additional user data with explicit created_at
            user_data = {
                "id": user_id,
                "username": username,
                "email": email,
                "full_name": full_name,
                "role": role,
                "created_at": datetime.datetime.now().isoformat()
            }
            
            user_response = supabase.table("users").insert(user_data).execute()
            
            if user_response.data:
                if role == "admin":
                    flash('Account created successfully! You are the first user, so you have been granted admin privileges.')
                else:
                    flash('Account created successfully! Please log in.')
                return redirect(url_for('index'))
            else:
                # If user data wasn't stored, delete the auth user
                try:
                    supabase.auth.admin.delete_user(user_id)
                except:
                    pass
                flash('Error creating user profile')
        else:
            flash('Error creating account')
            
        return redirect(url_for('register'))
    
    except Exception as e:
        print(f"Error creating account: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Error: {str(e)}')
        return redirect(url_for('register'))

@app.route('/login', methods=['POST'])
def login():
    print("Login route called")
    email = request.form.get('email')
    password = request.form.get('password')
    
    print(f"Login attempt for email: {email}")
    
    # Input validation
    if not email or not password:
        flash('Email and password are required')
        return redirect(url_for('index'))
    
    try:
        # Sign in with Supabase
        supabase = get_supabase_client()
        
        # First, check if the user exists in our users table
        user_check = supabase.table('users').select('*').eq('email', email).execute()
        print(f"User check: {user_check.data}")
        
        if not user_check.data:
            flash('User not found')
            return redirect(url_for('index'))
        
        # Now try to authenticate
        auth_response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        print(f"Auth response: {auth_response}")
        
        # Get user data from our previous query
        user = user_check.data[0]
        user_id = user['id']
        user_role = user.get('role', 'user')
        
        # Set session data
        session['user_id'] = user_id
        session['username'] = user.get('username')
        session['role'] = user_role
        session['logged_in'] = True
        
        print(f"Session data set: user_id={user_id}, username={user.get('username')}, role={user_role}")
        
        flash('Logged in successfully!')
        return redirect(url_for('home', category='anstalld'))
    
    except Exception as e:
        print(f"Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Check if it's an authentication error
        if "Invalid login credentials" in str(e):
            flash('Invalid email or password')
        else:
            flash(f'Login failed: {str(e)}')
            
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    # Clear session
    session.clear()
    flash('Du har loggats ut', 'info')
    return redirect(url_for('index'))

# Add direct routes for each category
@app.route('/anstalld')
@login_required
def anstalld_redirect():
    return redirect(url_for('home', category='anstalld'))

@app.route('/grupp')
@login_required
def grupp_redirect():
    return redirect(url_for('home', category='grupp'))

@app.route('/organisation')
@login_required
def organisation_redirect():
    return redirect(url_for('home', category='organisation'))

@app.route('/foretagsledning')
@login_required
def foretagsledning_redirect():
    return redirect(url_for('home', category='foretagsledning'))

@app.route('/managers-l6')
@login_required
def managers_redirect():
    return redirect(url_for('home', category='managers'))

@app.route('/supervisors-ac')
@login_required
def supervisors_redirect():
    return redirect(url_for('home', category='supervisors'))

@app.route('/admin_users')
@login_required
@admin_required
def admin_users_redirect():
    return redirect(url_for('admin_users'))

@app.route('/profile', methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "GET":
        try:
            # Get user from Supabase
            user = sb.supabase.table('users').select('*').eq('id', session['user_id']).execute()
            
            if not user.data:
                return redirect(url_for('logout'))
                
            return render_template("profile.html", user=user.data[0])
        except Exception as e:
            print(f"Profile error: {e}")
            flash('An error occurred while retrieving profile information', 'error')
            return redirect(url_for('home', category='anstalld'))
    
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_new_password = request.form.get("confirm_new_password")
        email = request.form.get("email")
        full_name = request.form.get("full_name")
        
        try:
            # Get user from Supabase
            user_response = sb.supabase.table('users').select('*').eq('id', session['user_id']).execute()
            
            if not user_response.data:
                return redirect(url_for('logout'))
                
            user = user_response.data[0]
            
            # Update password if provided
            if current_password and new_password:
                if new_password != confirm_new_password:
                    return render_template("profile.html", user=user, error="New passwords don't match")
                
                # Verify current password
                try:
                    # Try to sign in with current password
                    sb.supabase.auth.sign_in_with_password({
                        "email": user["email"],
                        "password": current_password
                    })
                    
                    # Update password
                    sb.supabase.auth.admin.update_user_by_id(
                        session['user_id'],
                        {"password": new_password}
                    )
                except Exception as e:
                    return render_template("profile.html", user=user, error="Current password is incorrect")
            
            # Update email and full name
            sb.update_user(session['user_id'], {
                'email': email,
                'full_name': full_name
            })
            
            flash('Profile information updated', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            print(f"Profile update error: {e}")
            return render_template("profile.html", user=user, error=f"An error occurred while updating profile: {str(e)}")

@app.route('/home/<category>')
@login_required
def home(category):
    # Update the list of valid categories
    valid_categories = [
        'anstalld', 'grupp', 'organisation', 'foretagsledning', 
        'managers', 'supervisors'
    ]
    
    if category not in valid_categories:
        return redirect(url_for('home', category='anstalld'))
    
    try:
        # Get items from Supabase
        items = sb.get_items(category)
        
        # Convert items to JSON for the template
        import json
        saved_items_json = json.dumps(items)
        
        # Get Supabase URL and key for client-side initialization
        supabase_url = os.environ.get("SUPABASE_URL", "")
        supabase_key = os.environ.get("SUPABASE_ANON_KEY", "")
        
        return render_template('index.html', 
                              items=items, 
                              saved_items_json=saved_items_json, 
                              current_category=category,
                              supabase_url=supabase_url,
                              supabase_key=supabase_key)
    except Exception as e:
        print(f"Error getting items: {e}")
        flash('Ett fel uppstod vid hämtning av data', 'error')
        return render_template('index.html', 
                              items=[], 
                              saved_items_json='[]', 
                              current_category=category,
                              supabase_url=os.environ.get("SUPABASE_URL", ""),
                              supabase_key=os.environ.get("SUPABASE_ANON_KEY", ""))

@app.route('/save_item', methods=['POST'])
@login_required
def save_item():
    try:
        data = request.json
        
        # Save item to Supabase
        sb.save_item(
            data['text'],
            data['entity'],
            data['risk_level'],
            data['position'],
            data['category'],
            session['user_id']
        )
        
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error saving item: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delete_item', methods=['POST'])
@login_required
def delete_item():
    try:
        data = request.json
        
        # Delete item from Supabase
        sb.delete_item(
            data['text'],
            data['entity'],
            data['risk_level'],
            data['category']
        )
        
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error deleting item: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Admin route to manage users
@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_users():
    try:
        print(f"Admin users route accessed by: {session.get('username')}, role: {session.get('role')}")
        
        # Get all users from Supabase
        users = sb.get_all_users()
        print(f"Retrieved {len(users)} users")
        
        # Check if there are any admin users
        admin_count = sb.count_users_by_role('admin')
        print(f"Admin count: {admin_count}")
        
        if admin_count == 0:
            flash('Warning: There are no administrators in the system. Create at least one administrator to ensure access to admin functions.', 'error')
        
        return render_template('admin_users.html', users=users)
    except Exception as e:
        print(f"Admin users error: {e}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while retrieving user information', 'error')
        return render_template('error.html', error='Failed to load admin users page')

@app.route('/admin/users/edit/<string:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user_admin(user_id):
    try:
        new_role = request.form.get('role')
        
        # Don't allow removing admin status from the last admin
        if new_role != 'admin' and sb.is_last_admin(user_id):
            flash('Cannot remove admin status from the last administrator', 'error')
            return redirect(url_for('admin_users'))
        
        # Update the user's role
        sb.update_user(user_id, {'role': new_role})
        
        flash('User role updated successfully', 'success')
        return redirect(url_for('admin_users'))
    except Exception as e:
        print(f"Update user error: {e}")
        flash('Error updating user', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<string:user_id>', methods=['GET'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        # Don't allow deleting yourself
        if user_id == session['user_id']:
            flash('You cannot delete your own account', 'error')
            return redirect(url_for('admin_users'))
            
        # Don't allow deleting the last admin
        if sb.is_last_admin(user_id):
            flash('Cannot delete the last administrator', 'error')
            return redirect(url_for('admin_users'))
        
        # Get the username for the flash message
        user_response = sb.supabase.table('users').select('username').eq('id', user_id).execute()
        
        if not user_response.data:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))
            
        username = user_response.data[0]['username']
        
        # Delete the user
        sb.delete_user(user_id)
        
        flash(f'User {username} has been deleted', 'success')
        return redirect(url_for('admin_users'))
    except Exception as e:
        print(f"Delete user error: {e}")
        flash('Error deleting user', 'error')
        return redirect(url_for('admin_users'))

@app.route('/get_resources', methods=['GET'])
@login_required
def get_resources():
    """
    Get all resources
    """
    try:
        resources = sb.get_resources()
        return jsonify({
            'status': 'success',
            'resources': resources
        })
    except Exception as e:
        print(f"Error getting resources: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/add_resource', methods=['POST'])
@login_required
def add_resource():
    """
    Add a new resource
    """
    try:
        data = request.get_json()
        text = data.get('text')
        user_id = session.get('user_id')  # This might be None if user is not logged in
        
        if not text:
            return jsonify({
                'status': 'error',
                'message': 'Text is required'
            }), 400
            
        # Pass user_id which might be None, the updated add_resource function will handle it
        resource = sb.add_resource(text, user_id)
        
        if resource:
            return jsonify({
                'status': 'success',
                'resource': resource
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to add resource'
            }), 500
    except Exception as e:
        print(f"Error adding resource: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/delete_resource', methods=['POST'])
@login_required
def delete_resource():
    """
    Delete a resource
    """
    try:
        data = request.get_json()
        resource_id = data.get('id')
        
        if not resource_id:
            return jsonify({
                'status': 'error',
                'message': 'Resource ID is required'
            }), 400
            
        success = sb.delete_resource(resource_id)
        
        if success:
            return jsonify({
                'status': 'success'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to delete resource'
            }), 500
    except Exception as e:
        print(f"Error deleting resource: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/update_resource', methods=['POST'])
@login_required
def update_resource():
    """
    Update a resource
    """
    try:
        data = request.get_json()
        resource_id = data.get('id')
        text = data.get('text')
        
        if not resource_id:
            return jsonify({
                'status': 'error',
                'message': 'Resource ID is required'
            }), 400
            
        if not text:
            return jsonify({
                'status': 'error',
                'message': 'Text is required'
            }), 400
            
        resource = sb.update_resource(resource_id, text)
        
        if resource:
            return jsonify({
                'status': 'success',
                'resource': resource
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update resource'
            }), 500
    except Exception as e:
        print(f"Error updating resource: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Register close_db function
app.teardown_appcontext(close_db)

# Initialize database on startup
with app.app_context():
    init_db()
    # Check and fix RLS policies
    sb.check_and_fix_rls_policies()

# Print the template folder path
print(f"Template folder: {app.template_folder}")

if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)
