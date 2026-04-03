"""
MySQL-specific models for PrivacyWeave Chatbot
These models mirror the PostgreSQL models but are optimized for MySQL
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from sqlalchemy.sql import func
from mysql_db import MySQLBase


class MySQLUser(MySQLBase):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    full_name = Column(String(150), nullable=False)
    role = Column(String(50), nullable=False)  
    age = Column(Integer, nullable=True)
    email = Column(String(100), unique=True, index=True, nullable=True)
    team = Column(String(50), nullable=True)  
    office_location = Column(String(100), nullable=True)
    salary = Column(Float, nullable=True)
    address_line = Column(Text, nullable=True)
    city = Column(String(50), nullable=True)
    state = Column(String(50), nullable=True)
    country = Column(String(50), nullable=True)
    postal_code = Column(String(12), nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class MySQLFAQ(MySQLBase):
    __tablename__ = "faqs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    category = Column(String(50), nullable=False)  
    question = Column(String(255), nullable=False)
    answer = Column(Text, nullable=False)
    visibility = Column(String(50), nullable=False, default="public")  
    created_at = Column(DateTime, server_default=func.now())


class MySQLChatLog(MySQLBase):
    __tablename__ = "chat_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_role = Column(String(50), nullable=False)
    user_name = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    sensitivity = Column(String(16), nullable=True)  # 'SENSITIVE' or 'OK'
    expires_at = Column(DateTime, nullable=True)


class MySQLRegister(MySQLBase):
    __tablename__ = "register"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(Text, unique=False, index=False, nullable=False)
    email_fp = Column(String(64), unique=True, index=True, nullable=True)
    main_id_password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)
    date_of_birth = Column(Text, nullable=True)
    government_id = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class MySQLLogin(MySQLBase):
    __tablename__ = "login"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class MySQLDataLeak(MySQLBase):
    __tablename__ = "data_leaks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(String(64), nullable=True, index=True)
    hr_name = Column(String(100), nullable=True)
    question = Column(Text, nullable=False)
    answer_preview = Column(Text, nullable=False)
    category = Column(String(50), nullable=True)  
    created_at = Column(DateTime, server_default=func.now())
    
    # Enhanced leak detection fields for dashboard
    risk_level = Column(String(20), nullable=True, default="low")  # low, medium, high, critical
    risk_score = Column(Integer, nullable=True, default=0)  # 0-100
    user_role = Column(String(50), nullable=True)  # Role of the user who triggered the leak
    target_role = Column(String(50), nullable=True)  # Role of the target being accessed
    leak_type = Column(String(50), nullable=True)  # Type of leak (PII, credentials, etc.)
    external_calls = Column(Integer, nullable=True, default=0)  # Number of external API calls
    risky_flows = Column(Integer, nullable=True, default=0)  # Number of risky conversation flows


class MySQLSecurityScanResults(MySQLBase):
    __tablename__ = "security_scan_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Security Scan Results - Persistent across sessions
    fake_names_count = Column(Integer, nullable=False, default=0)
    medical_records_count = Column(Integer, nullable=False, default=0)
    api_keys_count = Column(Integer, nullable=False, default=0)
    jailbreak_attempts_count = Column(Integer, nullable=False, default=0)
    pii_phi_secrets_count = Column(Integer, nullable=False, default=0)
    risky_flows_count = Column(Integer, nullable=False, default=0)
    external_calls_count = Column(Integer, nullable=False, default=0)
    
    # Results section
    resistance_percentage = Column(Integer, nullable=False, default=100)
    leaked_records_count = Column(Integer, nullable=False, default=0)
    
    # Metadata
    scan_date = Column(DateTime, server_default=func.now())
    hr_user = Column(String(100), nullable=True)  # HR user who performed the scan
    session_id = Column(String(64), nullable=True)  # Session when scan was performed
    is_latest = Column(Integer, nullable=False, default=1)  # 1 for latest, 0 for historical
