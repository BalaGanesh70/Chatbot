from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from sqlalchemy import func, text
import json
from datetime import datetime, timedelta

from config import settings
from db import Base, engine, get_db
from mysql_db import create_mysql_tables, MySQLSessionLocal
from mysql_models import MySQLUser
from sqlite_db import create_sqlite_tables, SQLiteSessionLocal
from sqlite_models import SQLiteUser
from mongodb_db import mongodb_manager
from models import User as PgUser
from schemas import ChatRequest, ChatResponse, RegisterRequest, RegisterResponse, LoginRequest, LoginResponse, DataLeakOut, SecurityScanResultsOut, ChatHistorySearchRequest, ChatHistoryCSVExportRequest
from logic import find_best_answer, log_interaction, normalize_role, set_analyzer_getter
from mirror import (
    mirror_chat_log_sync,
    mirror_register_sync,
    mirror_login_sync,
    mirror_security_scan_results_sync,
)
from models import Register as RegisterModel, Login as LoginModel, DataLeak as DataLeakModel, SecurityScanResults as SecurityScanResultsModel
from models import ChatLog as ChatLogModel
import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    from presidio_analyzer import AnalyzerEngine
except Exception:  
    AnalyzerEngine = None  

from blocklist import is_blocked


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    # Create tables for MySQL and SQLite
    try:
        create_mysql_tables()
        print("✅ MySQL tables created/verified")
    except Exception as e:
        print(f"⚠️ MySQL table creation failed/skipped: {e}")
    try:
        create_sqlite_tables()
        print("✅ SQLite tables created/verified")
    except Exception as e:
        print(f"⚠️ SQLite table creation failed/skipped: {e}")

    # Connect to MongoDB and ensure indexes
    try:
        await mongodb_manager.connect()
        mongodb_manager.connect_sync()
        await mongodb_manager.create_indexes()
        print("✅ MongoDB connected and indexes ensured")
    except Exception as e:
        print(f"⚠️ MongoDB init failed/skipped: {e}")

    # Seed baseline users data if empty in each database
    seed_users = [
        {"id": 1, "full_name": "Alice Johnson", "role": "HR Manager", "age": 34, "email": "alice.johnson@example.com", "team": "HR", "office_location": "New York", "salary": 65000, "address_line": "123 Main St", "city": "New York", "state": "NY", "country": "USA", "postal_code": "10001"},
        {"id": 2, "full_name": "Michael Smith", "role": "Tech Lead", "age": 41, "email": "michael.smith@example.com", "team": "Engineering", "office_location": "San Francisco", "salary": 120000, "address_line": "456 Market St", "city": "San Francisco", "state": "CA", "country": "USA", "postal_code": "94105"},
        {"id": 3, "full_name": "Priya Sharma", "role": "Intern", "age": 22, "email": "priya.sharma@example.com", "team": "Engineering", "office_location": "Bangalore", "salary": 15000, "address_line": "78 Residency Rd", "city": "Bangalore", "state": "KA", "country": "India", "postal_code": "560025"},
        {"id": 4, "full_name": "David Lee", "role": "Senior Engineer", "age": 37, "email": "david.lee@example.com", "team": "Engineering", "office_location": "Chicago", "salary": 95000, "address_line": "789 Lake Shore Dr", "city": "Chicago", "state": "IL", "country": "USA", "postal_code": "60611"},
        {"id": 5, "full_name": "Sophia Martinez", "role": "Product Manager", "age": 30, "email": "sophia.martinez@example.com", "team": "Product", "office_location": "Austin", "salary": 88000, "address_line": "654 Congress Ave", "city": "Austin", "state": "TX", "country": "USA", "postal_code": "73301"},
        {"id": 6, "full_name": "James Wilson", "role": "HR Associate", "age": 28, "email": "james.wilson@example.com", "team": "HR", "office_location": "New York", "salary": 48000, "address_line": "321 Park Ave", "city": "New York", "state": "NY", "country": "USA", "postal_code": "10022"},
        {"id": 7, "full_name": "Mei Chen", "role": "Senior Engineer", "age": 35, "email": "mei.chen@example.com", "team": "Engineering", "office_location": "Singapore", "salary": 102000, "address_line": "55 Orchard Rd", "city": "Singapore", "state": "SG", "country": "Singapore", "postal_code": "238880"},
        {"id": 8, "full_name": "Robert Brown", "role": "Tech Lead", "age": 40, "email": "robert.brown@example.com", "team": "Engineering", "office_location": "London", "salary": 115000, "address_line": "22 Baker St", "city": "London", "state": "LDN", "country": "UK", "postal_code": "W1U3BW"},
        {"id": 9, "full_name": "Isabella Rossi", "role": "Intern", "age": 23, "email": "isabella.rossi@example.com", "team": "Product", "office_location": "Milan", "salary": 18000, "address_line": "77 Via Roma", "city": "Milan", "state": "MI", "country": "Italy", "postal_code": "20121"},
        {"id": 10, "full_name": "Ahmed Khan", "role": "Senior Engineer", "age": 39, "email": "ahmed.khan@example.com", "team": "Engineering", "office_location": "Dubai", "salary": 99000, "address_line": "12 Sheikh Zayed Rd", "city": "Dubai", "state": "DU", "country": "UAE", "postal_code": "00000"}
    ]

    # PostgreSQL seed
    try:
        with engine.begin() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM users")).scalar() or 0
            if count == 0:
                for u in seed_users:
                    conn.execute(text("""
                        INSERT INTO users (id, full_name, role, age, email, team, office_location, salary, address_line, city, state, country, postal_code)
                        VALUES (:id, :full_name, :role, :age, :email, :team, :office_location, :salary, :address_line, :city, :state, :country, :postal_code)
                    """), u)
                print("✅ Seeded users in PostgreSQL")
    except Exception as e:
        print(f"⚠️ PostgreSQL seeding skipped: {e}")

    # MySQL seed
    try:
        mysql_db = MySQLSessionLocal()
        try:
            cnt = mysql_db.execute(text("SELECT COUNT(*) FROM users")).scalar() or 0
            if cnt == 0:
                for u in seed_users:
                    mysql_db.add(MySQLUser(**{k: v for k, v in u.items() if k in MySQLUser.__table__.columns}))
                mysql_db.commit()
                print("✅ Seeded users in MySQL")
        finally:
            mysql_db.close()
    except Exception as e:
        print(f"⚠️ MySQL seeding skipped: {e}")

    # SQLite seed
    try:
        sqlite_db = SQLiteSessionLocal()
        try:
            cnt = sqlite_db.execute(text("SELECT COUNT(*) FROM users")).scalar() or 0
            if cnt == 0:
                for u in seed_users:
                    sqlite_db.add(SQLiteUser(**{k: v for k, v in u.items() if k in SQLiteUser.__table__.columns}))
                sqlite_db.commit()
                print("✅ Seeded users in SQLite")
        finally:
            sqlite_db.close()
    except Exception as e:
        print(f"⚠️ SQLite seeding skipped: {e}")

    # MongoDB seed
    try:
        users_col = mongodb_manager.get_sync_collection("users")
        if users_col.count_documents({}) == 0:
            docs = []
            for u in seed_users:
                doc = u.copy()
                doc["_id"] = doc.pop("id")
                docs.append(doc)
            users_col.insert_many(docs)
            print("✅ Seeded users in MongoDB")
    except Exception as e:
        print(f"⚠️ MongoDB seeding skipped: {e}")
    try:
        with engine.begin() as conn:
            dialect = engine.dialect.name
            # Add missing columns for enhanced leak detection
            new_columns = [
                ("session_id", "VARCHAR(64)" if dialect == "postgresql" else "TEXT"),
                ("risk_level", "VARCHAR(20)" if dialect == "postgresql" else "TEXT"),
                ("risk_score", "INTEGER"),
                ("user_role", "VARCHAR(50)" if dialect == "postgresql" else "TEXT"),
                ("target_role", "VARCHAR(50)" if dialect == "postgresql" else "TEXT"),
                ("leak_type", "VARCHAR(50)" if dialect == "postgresql" else "TEXT"),
                ("external_calls", "INTEGER"),
                ("risky_flows", "INTEGER")
            ]
            
            for column_name, column_type in new_columns:
                try:
                    if dialect == "postgresql":
                        conn.execute(text(f"ALTER TABLE data_leaks ADD COLUMN IF NOT EXISTS {column_name} {column_type}"))
                    else:
                        # For SQLite, check if column exists first
                        try:
                            conn.execute(text(f"ALTER TABLE data_leaks ADD COLUMN {column_name} {column_type}"))
                            print(f"✅ Added column: {column_name}")
                        except Exception as e:
                            if "duplicate column name" in str(e).lower():
                                print(f"ℹ️ Column {column_name} already exists")
                            else:
                                print(f"⚠️ Could not add column {column_name}: {e}")
                except Exception as e:
                    print(f"⚠️ Column {column_name} migration skipped: {e}")

            # Ensure chat_logs has sensitivity and expires_at columns
            chatlog_columns = [
                ("sensitivity", "VARCHAR(16)" if dialect == "postgresql" else "TEXT"),
                ("expires_at", "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "DATETIME"),
            ]
            for column_name, column_type in chatlog_columns:
                try:
                    if dialect == "postgresql":
                        conn.execute(text(f"ALTER TABLE chat_logs ADD COLUMN IF NOT EXISTS {column_name} {column_type}"))
                    else:
                        try:
                            conn.execute(text(f"ALTER TABLE chat_logs ADD COLUMN {column_name} {column_type}"))
                            print(f"✅ Added chat_logs column: {column_name}")
                        except Exception as e:
                            if "duplicate column name" in str(e).lower():
                                print(f"ℹ️ chat_logs column {column_name} already exists")
                            else:
                                print(f"⚠️ Could not add chat_logs column {column_name}: {e}")
                except Exception as e:
                    print(f"⚠️ chat_logs column {column_name} migration skipped: {e}")
            
            # Set default values for existing records
            try:
                if dialect == "postgresql":
                    conn.execute(text("UPDATE data_leaks SET risk_level = 'low' WHERE risk_level IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET risk_score = 0 WHERE risk_score IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET leak_type = 'general' WHERE leak_type IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET external_calls = 0 WHERE external_calls IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET risky_flows = 0 WHERE risky_flows IS NULL"))
                else:
                    conn.execute(text("UPDATE data_leaks SET risk_level = 'low' WHERE risk_level IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET risk_score = 0 WHERE risk_score IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET leak_type = 'general' WHERE leak_type IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET external_calls = 0 WHERE external_calls IS NULL"))
                    conn.execute(text("UPDATE data_leaks SET risky_flows = 0 WHERE risky_flows IS NULL"))
                print("✅ Set default values for existing records")
            except Exception as e:
                print(f"⚠️ Default value update skipped: {e}")
            
            # Create security_scan_results table if it doesn't exist
            try:
                if dialect == "postgresql":
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS security_scan_results (
                            id SERIAL PRIMARY KEY,
                            fake_names_count INTEGER NOT NULL DEFAULT 0,
                            medical_records_count INTEGER NOT NULL DEFAULT 0,
                            api_keys_count INTEGER NOT NULL DEFAULT 0,
                            jailbreak_attempts_count INTEGER NOT NULL DEFAULT 0,
                            pii_phi_secrets_count INTEGER NOT NULL DEFAULT 0,
                            risky_flows_count INTEGER NOT NULL DEFAULT 0,
                            external_calls_count INTEGER NOT NULL DEFAULT 0,
                            resistance_percentage INTEGER NOT NULL DEFAULT 100,
                            leaked_records_count INTEGER NOT NULL DEFAULT 0,
                            scan_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                            hr_user VARCHAR(100),
                            session_id VARCHAR(64),
                            is_latest INTEGER NOT NULL DEFAULT 1
                        )
                    """))
                else:  # SQLite
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS security_scan_results (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            fake_names_count INTEGER NOT NULL DEFAULT 0,
                            medical_records_count INTEGER NOT NULL DEFAULT 0,
                            api_keys_count INTEGER NOT NULL DEFAULT 0,
                            jailbreak_attempts_count INTEGER NOT NULL DEFAULT 0,
                            pii_phi_secrets_count INTEGER NOT NULL DEFAULT 0,
                            risky_flows_count INTEGER NOT NULL DEFAULT 0,
                            external_calls_count INTEGER NOT NULL DEFAULT 0,
                            resistance_percentage INTEGER NOT NULL DEFAULT 100,
                            leaked_records_count INTEGER NOT NULL DEFAULT 0,
                            scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                            hr_user VARCHAR(100),
                            session_id VARCHAR(64),
                            is_latest INTEGER NOT NULL DEFAULT 1
                        )
                    """))
                print("✅ Security scan results table created/verified")
            except Exception as e:
                print(f"⚠️ Security scan results table creation skipped: {e}")
                
    except Exception as e:
        print(f"Startup migration failed: {e}")
    global analyzer
    analyzer = None
    try:
        if AnalyzerEngine is not None:
            analyzer = AnalyzerEngine()
            print("Presidio Analyzer initialized")
        else:
            print("Presidio Analyzer not available; classification disabled")
    except Exception as e:
        analyzer = None
        print(f"Presidio initialization failed: {e}")
    
    # Initialize analyzer getter in logic module
    _init_logic_analyzer()
    
    yield
    
    # Shutdown (if needed)
    pass


app = FastAPI(title="Organization Chatbot API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_analyzer():
    """Get the global Presidio Analyzer instance"""
    return analyzer


# Set the analyzer getter in logic module after analyzer is initialized
# This will be called in lifespan after analyzer is created
def _init_logic_analyzer():
    """Initialize analyzer getter in logic module"""
    try:
        set_analyzer_getter(get_analyzer)
    except Exception as e:
        print(f"⚠️ Failed to set analyzer getter: {e}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", response_model=RegisterResponse)
def register_user(payload: RegisterRequest, db: Session = Depends(get_db)):
    norm_username = payload.username.strip()
    norm_email = payload.email.strip()
    exists_username = (
        db.query(RegisterModel)
        .filter(func.lower(RegisterModel.username) == norm_username.lower())
        .first()
    )
    def email_fingerprint(email_value: str) -> str:
        key = settings.encryption_secret.encode("utf-8")
        return hashlib.sha256(key + email_value.lower().encode("utf-8")).hexdigest()

    email_fp_val = email_fingerprint(norm_email)
    exists_email = db.query(RegisterModel).filter(RegisterModel.email_fp == email_fp_val).first()
    if exists_username:
        raise HTTPException(status_code=400, detail="Username already taken")
    if exists_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    main_id_pwd_hash = hashlib.sha256(payload.main_id_password.strip().encode("utf-8")).hexdigest()
    
    excluded_from_classification = {"main_id_password", "username", "role"}
    payload_dict = payload.model_dump()

    sensitive_fields = set()
    if analyzer is not None:
        try:
            for field_name, raw_value in payload_dict.items():
                if field_name in excluded_from_classification:
                    continue
                if raw_value is None:
                    continue
                value_str = str(raw_value).strip()
                if not value_str:
                    continue
                results = analyzer.analyze(text=value_str, language="en")
                if any(r.score >= 0.5 for r in results):
                    sensitive_fields.add(field_name)
        except Exception as e:
            print(f"Presidio analyze failed: {e}")

    
    def encrypt(value: str) -> str:
        if not value:
            return value
        role_key = settings.get_role_key(payload.role)
        key = hashlib.sha256(role_key.encode("utf-8")).digest()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("utf-8")

    final_email = encrypt(norm_email) if "email" in sensitive_fields else norm_email
    final_dob = encrypt((payload.date_of_birth or "").strip()) if "date_of_birth" in sensitive_fields else payload.date_of_birth
    final_government_id = encrypt((payload.government_id or "").strip()) if "government_id" in sensitive_fields else payload.government_id

    user = RegisterModel(
        username=norm_username,
        email=final_email,
        email_fp=email_fp_val,
        main_id_password_hash=main_id_pwd_hash,
        role=normalize_role(payload.role),
        date_of_birth=final_dob,
        government_id=final_government_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    try:
        mirror_register_sync(user.username, user.email, user.email_fp, user.role)
    except Exception:
        pass
    return RegisterResponse(message="Registered successfully", user_id=user.id)


@app.post("/login", response_model=LoginResponse)
def login_user(payload: LoginRequest, db: Session = Depends(get_db)):
    norm_login_username = payload.username.strip()
    user = (
        db.query(RegisterModel)
        .filter(func.lower(RegisterModel.username) == norm_login_username.lower())
        .first()
    )
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    provided_hash = hashlib.sha256(payload.password.strip().encode("utf-8")).hexdigest()
    if provided_hash != user.main_id_password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_row = LoginModel(username=user.username, password_hash=user.main_id_password_hash)
    db.add(login_row)
    db.commit()
    try:
        mirror_login_sync(login_row.username, login_row.password_hash)
    except Exception:
        pass
    return LoginResponse(message="Login successful", name=user.username, role=user.role)


@app.get("/block-status")
def block_status(session_id: str, role: str | None = None):
    blocked, remaining = is_blocked(session_id, role)
    return {"blocked": blocked, "remaining": remaining}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest, db: Session = Depends(get_db)):
    blocked, _ = is_blocked(request.session_id or "", request.role)
    if blocked:
        try:
            mirror_chat_log_sync(normalize_role(request.role), request.name, request.message, "You are temporarily blocked", "SENSITIVE")
        except Exception:
            pass
        return ChatResponse(reply="You are temporarily blocked")

    normalized_role = normalize_role(request.role)
    
    answer, sensitivity = find_best_answer(db, request.message, normalized_role, request.name, request.session_id)
    
    if answer is None:
        answer = "I'm sorry, I was unable to process that request."
        
    log_interaction(db, normalized_role, request.name, request.message, answer, sensitivity)
    try:
        mirror_chat_log_sync(normalized_role, request.name, request.message, answer, sensitivity)
    except Exception:
        pass
    return ChatResponse(reply=answer)


@app.get("/data-leaks", response_model=list[DataLeakOut])
def list_data_leaks(session_id: str | None = None, db: Session = Depends(get_db)):
    q = db.query(DataLeakModel)
    if session_id:
        q = q.filter(DataLeakModel.session_id == session_id)
    leaks = q.order_by(DataLeakModel.created_at.desc()).limit(200).all()
    
    def summarize(leak: DataLeakModel) -> str:
        q = (leak.question or "").strip()
        if leak.category == "compensation":
            lower_q = q.lower()
            target = None
            for kw in [" of ", " for "]:
                if kw in lower_q:
                    idx = lower_q.rfind(kw)
                    if idx >= 0:
                        target = q[idx + len(kw):].strip().strip("? .")
                        break
            if not target:
                target = "the employee"
            return f"Asked the Salary for the employee \"{target}\""
        if leak.category == "contact_information":
            return "Requested contact information of an employee"
        if leak.category == "address":
            return "Requested address information of an employee"
        if leak.category == "jailbreak_attempt":
            return "Attempted to bypass security controls"
        if leak.category == "role_escalation":
            return "Attempted to escalate access privileges"
        if leak.category == "bulk_data_request":
            return "Requested bulk employee data"
        if leak.category == "employee_data_access":
            return "Accessed employee information"
        return "Accessed sensitive information"

    result = []
    for leak in leaks:
        # Safely get enhanced fields with fallbacks
        try:
            risk_level = getattr(leak, 'risk_level', None)
            risk_score = getattr(leak, 'risk_score', None)
            user_role = getattr(leak, 'user_role', None)
            target_role = getattr(leak, 'target_role', None)
            leak_type = getattr(leak, 'leak_type', None)
            external_calls = getattr(leak, 'external_calls', None)
            risky_flows = getattr(leak, 'risky_flows', None)
        except AttributeError:
            # Fields don't exist yet, use defaults
            risk_level = "low"
            risk_score = 0
            user_role = None
            target_role = None
            leak_type = "general"
            external_calls = 0
            risky_flows = 0
        
        item = {
            "id": leak.id,
            "session_id": leak.session_id,
            "hr_name": leak.hr_name,
            "question": leak.question,
            "answer_preview": leak.answer_preview,
            "category": leak.category,
            "created_at": leak.created_at,
            "summary": summarize(leak),
            # Enhanced leak detection fields for dashboard (with safe fallbacks)
            "risk_level": risk_level,
            "risk_score": risk_score,
            "user_role": user_role,
            "target_role": target_role,
            "leak_type": leak_type,
            "external_calls": external_calls,
            "risky_flows": risky_flows,
        }
        result.append(item)
    return result


@app.get("/leak-analytics")
def get_leak_analytics(db: Session = Depends(get_db)):
    """Get analytics and statistics about detected leaks for dashboard"""
    try:
        # Check if enhanced fields exist in the database
        try:
            # Test if enhanced fields exist
            test_query = db.query(DataLeakModel).first()
            if test_query:
                has_enhanced_fields = hasattr(test_query, 'risk_level')
            else:
                has_enhanced_fields = False
        except Exception:
            has_enhanced_fields = False
        
        if has_enhanced_fields:
            # Enhanced fields exist, use them
            risk_level_stats = db.query(
                DataLeakModel.risk_level,
                func.count(DataLeakModel.id).label('count')
            ).filter(DataLeakModel.risk_level.isnot(None)).group_by(DataLeakModel.risk_level).all()
            
            leak_type_stats = db.query(
                DataLeakModel.leak_type,
                func.count(DataLeakModel.id).label('count')
            ).filter(DataLeakModel.leak_type.isnot(None)).group_by(DataLeakModel.leak_type).all()
            
            user_role_stats = db.query(
                DataLeakModel.user_role,
                func.count(DataLeakModel.id).label('count')
            ).filter(DataLeakModel.user_role.isnot(None)).group_by(DataLeakModel.user_role).all()
            
            avg_risk_score = db.query(func.avg(DataLeakModel.risk_score)).scalar() or 0
            
            recent_high_risk = db.query(DataLeakModel).filter(
                DataLeakModel.risk_score >= 60,
                DataLeakModel.created_at >= (datetime.utcnow() - timedelta(days=1))
            ).count()
            
            total_external_calls = db.query(func.sum(DataLeakModel.external_calls)).scalar() or 0
            total_risky_flows = db.query(func.sum(DataLeakModel.risky_flows)).scalar() or 0
            
            fake_entities = db.query(DataLeakModel).filter(
                DataLeakModel.leak_type.in_(["compensation_data", "contact_information", "address_information"])
            ).count()
            
            jailbreak_attempts = db.query(DataLeakModel).filter(
                DataLeakModel.category == "jailbreak_attempt"
            ).count()
        else:
            # Enhanced fields don't exist, use basic fallbacks
            risk_level_stats = [{"level": "low", "count": 0}]
            leak_type_stats = [{"type": "general", "count": 0}]
            user_role_stats = [{"role": "unknown", "count": 0}]
            avg_risk_score = 0
            recent_high_risk = 0
            total_external_calls = 0
            total_risky_flows = 0
            fake_entities = 0
            jailbreak_attempts = 0
        
        # These fields should always exist
        category_stats = db.query(
            DataLeakModel.category,
            func.count(DataLeakModel.id).label('count')
        ).filter(DataLeakModel.category.isnot(None)).group_by(DataLeakModel.category).all()
        
        return {
            "risk_level_distribution": [{"level": stat.risk_level, "count": stat.count} for stat in risk_level_stats],
            "category_distribution": [{"category": stat.category, "count": stat.count} for stat in category_stats],
            "user_role_distribution": [{"role": stat.role, "count": stat.count} for stat in user_role_stats],
            "leak_type_distribution": [{"type": stat.type, "count": stat.count} for stat in leak_type_stats],
            "average_risk_score": round(avg_risk_score, 2),
            "recent_high_risk_leaks": recent_high_risk,
            "total_leaks": db.query(DataLeakModel).count(),
            "total_external_calls": total_external_calls,
            "total_risky_flows": total_risky_flows,
            "fake_entities_detected": fake_entities,
            "jailbreak_attempts": jailbreak_attempts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get leak analytics: {str(e)}")


@app.get("/leak-recommendations")
def get_security_recommendations(db: Session = Depends(get_db)):
    """Get security recommendations based on detected leaks"""
    try:
        # Get recent high-risk leaks
        recent_high_risk = db.query(DataLeakModel).filter(
            DataLeakModel.risk_score >= 40
        ).order_by(DataLeakModel.created_at.desc()).limit(10).all()
        
        recommendations = []
        
        # Analyze patterns and generate recommendations
        for leak in recent_high_risk:
            if leak.leak_type == "compensation_data" and leak.user_role != "HR":
                recommendations.append("Add guardrails for prompt injection to prevent compensation data access")
            
            if leak.leak_type == "bulk_data_request":
                recommendations.append("Block external calls to risky APIs for bulk data requests")
            
            if leak.risk_score >= 60:
                recommendations.append("Encrypt/tokenize PHI before model calls")
            
            if leak.user_role in ["Applicant", "Visitor"] and leak.risk_score > 30:
                recommendations.append("Implement stricter access controls for external users")
        
        # Add general recommendations based on overall statistics
        total_leaks = db.query(DataLeakModel).count()
        if total_leaks > 10:
            recommendations.append("Review and update access control policies")
        
        high_risk_count = db.query(DataLeakModel).filter(DataLeakModel.risk_score >= 60).count()
        if high_risk_count > 5:
            recommendations.append("Implement additional security monitoring and alerting")
        
        # Remove duplicates and return top recommendations
        unique_recs = list(set(recommendations))
        
        return {
            "recommendations": unique_recs[:5],
            "total_recommendations": len(unique_recs),
            "high_risk_leaks": high_risk_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {str(e)}")


@app.get("/dashboard-summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Get comprehensive dashboard summary similar to the image format"""
    try:
        # Get basic counts
        total_leaks = db.query(DataLeakModel).count()
        
        # Check if enhanced fields exist
        try:
            test_query = db.query(DataLeakModel).first()
            if test_query:
                has_enhanced_fields = hasattr(test_query, 'leak_type')
            else:
                has_enhanced_fields = False
        except Exception:
            has_enhanced_fields = False
        
        if has_enhanced_fields:
            # Enhanced fields exist, use them
            fake_names = db.query(DataLeakModel).filter(
                DataLeakModel.leak_type == "compensation_data"
            ).count()
            
            medical_records = db.query(DataLeakModel).filter(
                DataLeakModel.leak_type == "sensitive_data"
            ).count()
            
            api_keys = db.query(DataLeakModel).filter(
                DataLeakModel.leak_type == "credentials"
            ).count()
            

            
            jailbreak_prompts = db.query(DataLeakModel).filter(
                DataLeakModel.category == "jailbreak_attempt"
            ).count()
            
            pii_phi_secrets = db.query(DataLeakModel).filter(
                DataLeakModel.risk_score >= 30
            ).count()
            
            external_calls = db.query(func.sum(DataLeakModel.external_calls)).scalar() or 0
            
            risky_flows = db.query(func.sum(DataLeakModel.risky_flows)).scalar() or 0
        else:
            # Enhanced fields don't exist, use basic fallbacks
            fake_names = sum(1 for leak in db.query(DataLeakModel).all() 
                           if "salary" in (leak.question or "").lower())
            medical_records = sum(1 for leak in db.query(DataLeakModel).all() 
                                if "medical" in (leak.question or "").lower())
            
            api_keys = sum(1 for leak in db.query(DataLeakModel).all() 
                          if "api" in (leak.question or "").lower())

            
            jailbreak_prompts = sum(1 for leak in db.query(DataLeakModel).all() 
                                   if any(word in (leak.question or "").lower() 
                                         for word in ["ignore", "bypass", "admin", "system"]))
            
            pii_phi_secrets = sum(1 for leak in db.query(DataLeakModel).all() 
                                 if any(word in (leak.question or "").lower() 
                                       for word in ["salary", "email", "phone", "address", "contact"]))
            
            external_calls = 0
            risky_flows = 0
        
        # Calculate resistance percentage (simplified)
        total_attempts = total_leaks + 10  # Add some baseline
        resisted_attempts = total_attempts - total_leaks
        resistance_percentage = min(100, max(0, int((resisted_attempts / total_attempts) * 100)))
        
        # Count third-party connections (simplified)
        third_party_connections = external_calls
        high_risk_connections = db.query(DataLeakModel).filter(
            DataLeakModel.risk_score >= 60
        ).count() if has_enhanced_fields else 0
        
        return {
            "fake_entities": {
                "fake_names": fake_names,
                "medical_records": medical_records,
                "api_keys": api_keys
            },
            "jailbreak_prompts": jailbreak_prompts,
            "ai_behavior": {
                "pii_phi_secrets": pii_phi_secrets,
                "external_calls": external_calls,
                "risky_flows": risky_flows
            },
            "results": {
                "resistance_percentage": resistance_percentage,
                "leaked_records": total_leaks
            },
            "connections": {
                "third_party": third_party_connections,
                "high_risk": high_risk_connections
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard summary: {str(e)}")


@app.post("/analyze-text")
def analyze_text_with_presidio(request: dict):
    """Analyze text using Presidio for PII detection"""
    try:
        text = request.get("text", "")
        if not text:
            return {"entities": []}
        
        if analyzer is None:
            return {"entities": []}
        
        # Analyze text with Presidio
        results = analyzer.analyze(text=text, language="en")
        
        # Extract entity information
        entities = []
        for result in results:
            if result.score >= 0.5:  # Only include high-confidence detections
                entities.append({
                    "entity_type": result.entity_type,
                    "start": result.start,
                    "end": result.end,
                    "score": result.score,
                    "text": text[result.start:result.end]
                })
        
        return {"entities": entities}
    except Exception as e:
        print(f"Presidio analysis failed: {e}")
        return {"entities": []}


@app.get("/security-scan-results", response_model=SecurityScanResultsOut)
def get_latest_security_scan_results(db: Session = Depends(get_db)):
    """Get the latest security scan results (persistent across sessions)"""
    try:
        # Get the latest security scan results
        latest_scan = db.query(SecurityScanResultsModel).filter(
            SecurityScanResultsModel.is_latest == 1
        ).order_by(SecurityScanResultsModel.scan_date.desc()).first()
        
        if not latest_scan:
            # Create default scan results if none exist
            default_scan = SecurityScanResultsModel(
                fake_names_count=0,
                medical_records_count=0,
                api_keys_count=0,
                jailbreak_attempts_count=0,
                pii_phi_secrets_count=0,
                risky_flows_count=0,
                external_calls_count=0,
                resistance_percentage=100,
                leaked_records_count=0,
                is_latest=1
            )
            db.add(default_scan)
            db.commit()
            db.refresh(default_scan)
            try:
                mirror_security_scan_results_sync({
                    "fake_names_count": default_scan.fake_names_count,
                    "medical_records_count": default_scan.medical_records_count,
                    "api_keys_count": default_scan.api_keys_count,
                    "jailbreak_attempts_count": default_scan.jailbreak_attempts_count,
                    "pii_phi_secrets_count": default_scan.pii_phi_secrets_count,
                    "risky_flows_count": default_scan.risky_flows_count,
                    "external_calls_count": default_scan.external_calls_count,
                    "resistance_percentage": default_scan.resistance_percentage,
                    "leaked_records_count": default_scan.leaked_records_count,
                    "hr_user": default_scan.hr_user,
                    "session_id": default_scan.session_id,
                    "is_latest": default_scan.is_latest,
                })
            except Exception:
                pass
            return default_scan
        
        return latest_scan
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get security scan results: {str(e)}")


@app.post("/security-scan-results", response_model=SecurityScanResultsOut)
def save_security_scan_results(request: dict, db: Session = Depends(get_db)):
    """Save new security scan results and mark previous ones as historical"""
    try:
        # Mark all existing scans as historical
        db.query(SecurityScanResultsModel).update({SecurityScanResultsModel.is_latest: 0})
        
        # Create new scan results
        new_scan = SecurityScanResultsModel(
            fake_names_count=request.get("fake_names_count", 0),
            medical_records_count=request.get("medical_records_count", 0),
            api_keys_count=request.get("api_keys_count", 0),
            jailbreak_attempts_count=request.get("jailbreak_attempts_count", 0),
            pii_phi_secrets_count=request.get("pii_phi_secrets_count", 0),
            risky_flows_count=request.get("risky_flows_count", 0),
            external_calls_count=request.get("external_calls_count", 0),
            resistance_percentage=request.get("resistance_percentage", 100),
            leaked_records_count=request.get("leaked_records_count", 0),
            hr_user=request.get("hr_user"),
            session_id=request.get("session_id"),
            is_latest=1
        )
        
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        try:
            mirror_security_scan_results_sync({
                "fake_names_count": new_scan.fake_names_count,
                "medical_records_count": new_scan.medical_records_count,
                "api_keys_count": new_scan.api_keys_count,
                "jailbreak_attempts_count": new_scan.jailbreak_attempts_count,
                "pii_phi_secrets_count": new_scan.pii_phi_secrets_count,
                "risky_flows_count": new_scan.risky_flows_count,
                "external_calls_count": new_scan.external_calls_count,
                "resistance_percentage": new_scan.resistance_percentage,
                "leaked_records_count": new_scan.leaked_records_count,
                "hr_user": new_scan.hr_user,
                "session_id": new_scan.session_id,
                "is_latest": new_scan.is_latest,
            })
        except Exception:
            pass
        return new_scan
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to save security scan results: {str(e)}")


@app.get("/security-scan-history", response_model=list[SecurityScanResultsOut])
def get_security_scan_history(db: Session = Depends(get_db), limit: int = 10):
    """Get historical security scan results"""
    try:
        scans = db.query(SecurityScanResultsModel).order_by(
            SecurityScanResultsModel.scan_date.desc()
        ).limit(limit).all()
        return scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get security scan history: {str(e)}")


@app.get("/debug-security-scan")
def debug_security_scan_results(db: Session = Depends(get_db)):
    """Debug endpoint to check security scan results"""
    try:
        # Get all security scan results
        all_scans = db.query(SecurityScanResultsModel).all()
        
        # Get the latest scan
        latest_scan = db.query(SecurityScanResultsModel).filter(
            SecurityScanResultsModel.is_latest == 1
        ).first()
        
        return {
            "total_scans": len(all_scans),
            "latest_scan": {
                "id": latest_scan.id if latest_scan else None,
                "fake_names_count": latest_scan.fake_names_count if latest_scan else 0,
                "medical_records_count": latest_scan.medical_records_count if latest_scan else 0,
                "api_keys_count": latest_scan.api_keys_count if latest_scan else 0,
                "jailbreak_attempts_count": latest_scan.jailbreak_attempts_count if latest_scan else 0,
                "pii_phi_secrets_count": latest_scan.pii_phi_secrets_count if latest_scan else 0,
                "risky_flows_count": latest_scan.risky_flows_count if latest_scan else 0,
                "external_calls_count": latest_scan.external_calls_count if latest_scan else 0,
                "resistance_percentage": latest_scan.resistance_percentage if latest_scan else 100,
                "leaked_records_count": latest_scan.leaked_records_count if latest_scan else 0,
                "is_latest": latest_scan.is_latest if latest_scan else 0,
                "scan_date": str(latest_scan.scan_date) if latest_scan else None
            } if latest_scan else None,
            "all_scans": [
                {
                    "id": scan.id,
                    "fake_names_count": scan.fake_names_count,
                    "medical_records_count": scan.medical_records_count,
                    "is_latest": scan.is_latest,
                    "scan_date": str(scan.scan_date)
                } for scan in all_scans
            ]
        }
    except Exception as e:
        return {"error": str(e)}


@app.delete("/data-leaks")
def delete_session_leaks(session_id: str, db: Session = Depends(get_db)):
    if not session_id:
        return {"deleted": 0}
    try:
        deleted = db.query(DataLeakModel).filter(DataLeakModel.session_id == session_id).delete()
        db.commit()
        return {"deleted": deleted}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/chat-history")
def get_chat_history(role: str, db: Session = Depends(get_db)):
    try:
        if not role:
            raise HTTPException(status_code=400, detail="role is required")
        # Purge expired first
        try:
            db.query(ChatLogModel).filter(ChatLogModel.expires_at.isnot(None)).filter(text("expires_at <= CURRENT_TIMESTAMP")).delete(synchronize_session=False)
            db.flush()
            db.commit()
        except Exception:
            db.rollback()
        rows = (
            db.query(ChatLogModel)
            .filter(ChatLogModel.user_role == role)
            .order_by(ChatLogModel.created_at.desc())
            .limit(30)
            .all()
        )
        result = []
        for r in rows:
            result.append({
                "id": r.id,
                "created_at": r.created_at,
                "user_role": r.user_role,
                "user_name": r.user_name,
                "message": r.message,
                "response": r.response,
                "sensitivity": getattr(r, "sensitivity", None),
            })
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load chat history: {e}")


@app.delete("/chat-history/{chat_id}")
def delete_chat_history(chat_id: int, db: Session = Depends(get_db)):
    try:
        deleted = db.query(ChatLogModel).filter(ChatLogModel.id == chat_id).delete()
        db.commit()
        return {"deleted": int(deleted)}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete chat: {e}")


@app.post("/chat-history/search")
def search_chat_history(request: ChatHistorySearchRequest, db: Session = Depends(get_db)):
    """Simple search chat history by keywords"""
    try:
        if not request.role:
            raise HTTPException(status_code=400, detail="role is required")
        
        # Purge expired first
        try:
            db.query(ChatLogModel).filter(ChatLogModel.expires_at.isnot(None)).filter(text("expires_at <= CURRENT_TIMESTAMP")).delete(synchronize_session=False)
            db.flush()
            db.commit()
        except Exception:
            db.rollback()
        
        # Build query
        query = db.query(ChatLogModel).filter(ChatLogModel.user_role == request.role)
        
        # Apply search filter if provided
        if request.search_query:
            search_term = f"%{request.search_query}%"
            query = query.filter(
                (ChatLogModel.message.ilike(search_term)) |
                (ChatLogModel.response.ilike(search_term)) |
                (ChatLogModel.user_name.ilike(search_term))
            )
        
        # Execute query
        rows = query.order_by(ChatLogModel.created_at.desc()).limit(30).all()
        
        result = []
        for r in rows:
            result.append({
                "id": r.id,
                "created_at": r.created_at,
                "user_role": r.user_role,
                "user_name": r.user_name,
                "message": r.message,
                "response": r.response,
                "sensitivity": getattr(r, "sensitivity", None),
            })
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search chat history: {e}")


@app.post("/chat-history/export-csv")
def export_chat_history_csv(request: ChatHistoryCSVExportRequest, db: Session = Depends(get_db)):
    """Export chat history as CSV"""
    try:
        import csv
        import io
        from fastapi.responses import StreamingResponse
        
        if not request.role:
            raise HTTPException(status_code=400, detail="role is required for chat history export")
        
        # Build query for chat history
        query = db.query(ChatLogModel).filter(ChatLogModel.user_role == request.role)
        
        # Apply search filter if provided
        if request.search_query:
            search_term = f"%{request.search_query}%"
            query = query.filter(
                (ChatLogModel.message.ilike(search_term)) |
                (ChatLogModel.response.ilike(search_term)) |
                (ChatLogModel.user_name.ilike(search_term))
            )
        
        rows = query.order_by(ChatLogModel.created_at.desc()).all()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Created At', 'User Role', 'User Name', 'Message', 'Response', 'Sensitivity'])
        
        # Write data
        for row in rows:
            writer.writerow([
                row.id,
                row.created_at.isoformat() if row.created_at else '',
                row.user_role or '',
                row.user_name or '',
                row.message or '',
                row.response or '',
                getattr(row, 'sensitivity', '') or ''
            ])
        
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode('utf-8')),
            media_type='text/csv',
            headers={"Content-Disposition": f"attachment; filename=chat_history_{request.role}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export CSV: {e}")