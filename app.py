import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the PostgreSQL database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy with app
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Import utility modules
from utils.detector import detect_sensitive_data
from utils.classifier import classify_text

# Import models after db is defined but before creating tables
from models import User, Configuration, ScanHistory

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables within app context
with app.app_context():
    db.create_all()
    # Create default configuration if it doesn't exist
    default_config = Configuration.query.filter_by(is_default=True).first()
    if not default_config:
        default_config = Configuration(
            name="Default Configuration",
            is_default=True,
            scan_api_keys=True,
            scan_passwords=True,
            scan_credit_cards=True,
            scan_personal_info=True,
            scan_company_info=True,
            sensitivity_level=2  # Medium sensitivity (1-low, 2-medium, 3-high)
        )
        db.session.add(default_config)
        db.session.commit()
        logger.info("Created default configuration")

# Route for the home page
@app.route('/')
def index():
    return render_template('index.html')

# Route for the dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's configurations or default if none exists
    user_configs = Configuration.query.filter_by(user_id=current_user.id).all()
    if not user_configs:
        user_configs = [Configuration.query.filter_by(is_default=True).first()]
    
    # Get scan history for the user
    scan_history = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html', 
                          configurations=user_configs, 
                          scan_history=scan_history,
                          current_user=current_user)

# Route for analyzing text
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        # Check if request is JSON or form data
        if request.is_json:
            data = request.json
            text = data.get('text', '')
            config_id = data.get('config_id')
        else:
            text = request.form.get('text', '')
            config_id = request.form.get('config_id')
        
        logger.debug(f"Analyzing text (length: {len(text)}) with config_id: {config_id}")
        
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Determine which configuration to use
        if current_user.is_authenticated and config_id:
            config = Configuration.query.get(config_id)
            if not config or (config.user_id != current_user.id and not config.is_default):
                config = Configuration.query.filter_by(is_default=True).first()
        else:
            config = Configuration.query.filter_by(is_default=True).first()
        
        # Make sure we have a valid config
        if not config:
            logger.warning("No valid configuration found, creating default")
            config = Configuration(
                name="Default Configuration",
                is_default=True,
                scan_api_keys=True,
                scan_passwords=True,
                scan_credit_cards=True,
                scan_personal_info=True,
                scan_company_info=True,
                sensitivity_level=2
            )
        
        # Analyze the text for sensitive data
        results = detect_sensitive_data(text, config)
        
        try:
            # Classify the content using NLP
            classification = classify_text(text)
            results['classification'] = classification
        except Exception as e:
            logger.error(f"Error in classification: {str(e)}")
            results['classification'] = {}
    except Exception as e:
        logger.error(f"Error in analyze route: {str(e)}")
        return jsonify({
            "error": "An error occurred during analysis",
            "detections": {},
            "risk_level": "Error",
            "recommendations": ["The system encountered an error. Please try again."]
        }), 500
    
    # If user is logged in, save scan history
    if current_user.is_authenticated:
        scan = ScanHistory(
            user_id=current_user.id,
            text_sample=text[:100] + ('...' if len(text) > 100 else ''),
            detection_count=sum(len(detections) for detections in results['detections'].values()),
            risk_level=results['risk_level']
        )
        db.session.add(scan)
        db.session.commit()
    
    return jsonify(results)

# Routes for user authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('index.html', show_login=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('index.html', show_register=True)
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('index.html', show_register=True)
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        
        # Log in the user
        login_user(new_user)
        return redirect(url_for('dashboard'))
    
    return render_template('index.html', show_register=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Routes for configuration management
@app.route('/config/create', methods=['POST'])
@login_required
def create_config():
    name = request.form.get('name', 'My Configuration')
    
    new_config = Configuration(
        name=name,
        user_id=current_user.id,
        scan_api_keys=request.form.get('scan_api_keys') == 'on',
        scan_passwords=request.form.get('scan_passwords') == 'on',
        scan_credit_cards=request.form.get('scan_credit_cards') == 'on',
        scan_personal_info=request.form.get('scan_personal_info') == 'on',
        scan_company_info=request.form.get('scan_company_info') == 'on',
        sensitivity_level=int(request.form.get('sensitivity_level', 2))
    )
    
    db.session.add(new_config)
    db.session.commit()
    
    flash(f'Configuration "{name}" created successfully')
    return redirect(url_for('dashboard'))

@app.route('/config/edit/<int:config_id>', methods=['POST'])
@login_required
def edit_config(config_id):
    config = Configuration.query.get(config_id)
    
    # Check if configuration exists and belongs to the user
    if not config or (config.user_id != current_user.id and not config.is_default):
        flash('Configuration not found')
        return redirect(url_for('dashboard'))
    
    # Only allow editing default config if the user is an admin (future feature)
    if config.is_default and current_user.id != 1:  # Assuming admin has ID 1
        flash('You cannot edit the default configuration')
        return redirect(url_for('dashboard'))
    
    # Update configuration
    config.name = request.form.get('name', config.name)
    config.scan_api_keys = request.form.get('scan_api_keys') == 'on'
    config.scan_passwords = request.form.get('scan_passwords') == 'on'
    config.scan_credit_cards = request.form.get('scan_credit_cards') == 'on'
    config.scan_personal_info = request.form.get('scan_personal_info') == 'on'
    config.scan_company_info = request.form.get('scan_company_info') == 'on'
    config.sensitivity_level = int(request.form.get('sensitivity_level', config.sensitivity_level))
    
    db.session.commit()
    
    flash(f'Configuration "{config.name}" updated successfully')
    return redirect(url_for('dashboard'))

@app.route('/config/delete/<int:config_id>', methods=['POST'])
@login_required
def delete_config(config_id):
    config = Configuration.query.get(config_id)
    
    # Check if configuration exists and belongs to the user
    if not config or (config.user_id != current_user.id):
        flash('Configuration not found')
        return redirect(url_for('dashboard'))
    
    # Prevent deletion of default configuration
    if config.is_default:
        flash('Cannot delete the default configuration')
        return redirect(url_for('dashboard'))
    
    # Delete configuration
    db.session.delete(config)
    db.session.commit()
    
    flash('Configuration deleted successfully')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
