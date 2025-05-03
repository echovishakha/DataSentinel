from datetime import datetime
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    configurations = db.relationship('Configuration', backref='user', lazy=True)
    scan_history = db.relationship('ScanHistory', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Configuration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_default = db.Column(db.Boolean, default=False)
    
    # Detection settings
    scan_api_keys = db.Column(db.Boolean, default=True)
    scan_passwords = db.Column(db.Boolean, default=True)
    scan_credit_cards = db.Column(db.Boolean, default=True)
    scan_personal_info = db.Column(db.Boolean, default=True)
    scan_company_info = db.Column(db.Boolean, default=True)
    
    # Sensitivity level (1-3): 1=Low, 2=Medium, 3=High
    sensitivity_level = db.Column(db.Integer, default=2)
    
    # Additional settings
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Configuration {self.name}>'

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    text_sample = db.Column(db.String(255))  # Store a sample of the text (truncated)
    detection_count = db.Column(db.Integer, default=0)  # Number of sensitive data items detected
    risk_level = db.Column(db.String(20))  # Low, Medium, High
    
    def __repr__(self):
        return f'<ScanHistory {self.id}>'

class SensitiveDataDefinition(db.Model):
    """Model for custom sensitive data definitions that users can create"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(255))
    pattern = db.Column(db.String(255))  # Regex pattern for detection
    example = db.Column(db.String(255))  # Non-sensitive example for documentation
    category = db.Column(db.String(64))  # e.g., API Key, Password, Personal Info
    severity = db.Column(db.Integer)  # 1-3: 1=Low, 2=Medium, 3=High
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<SensitiveDataDefinition {self.name}>'
