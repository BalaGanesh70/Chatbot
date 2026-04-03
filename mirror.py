from sqlalchemy import text
from datetime import datetime

from mysql_db import MySQLSessionLocal
from sqlite_db import SQLiteSessionLocal
from mongodb_db import mongodb_manager


def mirror_chat_log_sync(user_role: str, user_name: str | None, message: str, response: str, sensitivity: str | None) -> None:
    """Write chat log to MySQL, SQLite, and MongoDB (sync). Failures are ignored."""
    chat_row = {
        "user_role": user_role,
        "user_name": user_name,
        "message": message,
        "response": response,
        "sensitivity": sensitivity,
        "expires_at": None,
        "created_at": datetime.utcnow(),
    }

    # MySQL
    try:
        db = MySQLSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO chat_logs (user_role, user_name, message, response, sensitivity, expires_at, created_at)
                    VALUES (:user_role, :user_name, :message, :response, :sensitivity, :expires_at, :created_at)
                    """
                ),
                chat_row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # SQLite
    try:
        db = SQLiteSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO chat_logs (user_role, user_name, message, response, sensitivity, expires_at, created_at)
                    VALUES (:user_role, :user_name, :message, :response, :sensitivity, :expires_at, :created_at)
                    """
                ),
                chat_row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # MongoDB (sync)
    try:
        mongodb_manager.connect_sync()
        col = mongodb_manager.get_sync_collection("chat_logs")
        doc = {
            "user_role": user_role,
            "user_name": user_name,
            "message": message,
            "response": response,
            "sensitivity": sensitivity,
            "created_at": datetime.utcnow(),
        }
        col.insert_one(doc)
    except Exception:
        pass



def mirror_data_leak_sync(
    session_id: str | None,
    hr_name: str | None,
    question: str,
    answer_preview: str,
    category: str | None,
    risk_level: str | None,
    risk_score: int | None,
    user_role: str | None,
    target_role: str | None,
    leak_type: str | None,
    external_calls: int | None,
    risky_flows: int | None,
) -> None:
    """Write data leak to MySQL, SQLite, and MongoDB (sync). Failures are ignored."""
    row = {
        "session_id": session_id,
        "hr_name": hr_name,
        "question": question,
        "answer_preview": answer_preview,
        "category": category,
        "risk_level": risk_level or "low",
        "risk_score": risk_score or 0,
        "user_role": user_role,
        "target_role": target_role,
        "leak_type": leak_type or "general",
        "external_calls": external_calls or 0,
        "risky_flows": risky_flows or 0,
        "created_at": datetime.utcnow(),
    }

    # MySQL
    try:
        db = MySQLSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO data_leaks (
                        session_id, hr_name, question, answer_preview, category,
                        created_at, risk_level, risk_score, user_role, target_role,
                        leak_type, external_calls, risky_flows
                    ) VALUES (
                        :session_id, :hr_name, :question, :answer_preview, :category,
                        :created_at, :risk_level, :risk_score, :user_role, :target_role,
                        :leak_type, :external_calls, :risky_flows
                    )
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # SQLite
    try:
        db = SQLiteSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO data_leaks (
                        session_id, hr_name, question, answer_preview, category,
                        created_at, risk_level, risk_score, user_role, target_role,
                        leak_type, external_calls, risky_flows
                    ) VALUES (
                        :session_id, :hr_name, :question, :answer_preview, :category,
                        :created_at, :risk_level, :risk_score, :user_role, :target_role,
                        :leak_type, :external_calls, :risky_flows
                    )
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # MongoDB (sync)
    try:
        mongodb_manager.connect_sync()
        col = mongodb_manager.get_sync_collection("data_leaks")
        doc = {k: v for k, v in row.items() if k}
        col.insert_one(doc)
    except Exception:
        pass



def mirror_register_sync(username: str, email: str, email_fp: str, role: str, created_at: datetime | None = None) -> None:
    row = {
        "username": username,
        "email": email,
        "email_fp": email_fp,
        "role": role,
        "created_at": created_at or datetime.utcnow(),
    }

    # MySQL
    try:
        db = MySQLSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO register (username, email, email_fp, main_id_password_hash, role, date_of_birth, government_id, created_at)
                    VALUES (:username, :email, :email_fp, '', :role, NULL, NULL, :created_at)
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # SQLite
    try:
        db = SQLiteSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO register (username, email, email_fp, main_id_password_hash, role, date_of_birth, government_id, created_at)
                    VALUES (:username, :email, :email_fp, '', :role, NULL, NULL, :created_at)
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # MongoDB
    try:
        mongodb_manager.connect_sync()
        col = mongodb_manager.get_sync_collection("register")
        doc = {
            "username": username,
            "email": email,
            "email_fp": email_fp,
            "role": role,
            "created_at": row["created_at"],
        }
        col.insert_one(doc)
    except Exception:
        pass



def mirror_login_sync(username: str, password_hash: str, created_at: datetime | None = None) -> None:
    row = {
        "username": username,
        "password_hash": password_hash,
        "created_at": created_at or datetime.utcnow(),
    }

    # MySQL
    try:
        db = MySQLSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO login (username, password_hash, created_at)
                    VALUES (:username, :password_hash, :created_at)
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # SQLite
    try:
        db = SQLiteSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO login (username, password_hash, created_at)
                    VALUES (:username, :password_hash, :created_at)
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # MongoDB
    try:
        mongodb_manager.connect_sync()
        col = mongodb_manager.get_sync_collection("login")
        col.insert_one(row)
    except Exception:
        pass



def mirror_security_scan_results_sync(scan: dict) -> None:
    # scan should contain keys corresponding to security_scan_results columns
    row = scan.copy()
    if "scan_date" not in row:
        row["scan_date"] = datetime.utcnow()

    # MySQL
    try:
        db = MySQLSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO security_scan_results (
                        fake_names_count, medical_records_count, api_keys_count, jailbreak_attempts_count,
                        pii_phi_secrets_count, risky_flows_count, external_calls_count,
                        resistance_percentage, leaked_records_count, scan_date, hr_user, session_id, is_latest
                    ) VALUES (
                        :fake_names_count, :medical_records_count, :api_keys_count, :jailbreak_attempts_count,
                        :pii_phi_secrets_count, :risky_flows_count, :external_calls_count,
                        :resistance_percentage, :leaked_records_count, :scan_date, :hr_user, :session_id, :is_latest
                    )
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # SQLite
    try:
        db = SQLiteSessionLocal()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO security_scan_results (
                        fake_names_count, medical_records_count, api_keys_count, jailbreak_attempts_count,
                        pii_phi_secrets_count, risky_flows_count, external_calls_count,
                        resistance_percentage, leaked_records_count, scan_date, hr_user, session_id, is_latest
                    ) VALUES (
                        :fake_names_count, :medical_records_count, :api_keys_count, :jailbreak_attempts_count,
                        :pii_phi_secrets_count, :risky_flows_count, :external_calls_count,
                        :resistance_percentage, :leaked_records_count, :scan_date, :hr_user, :session_id, :is_latest
                    )
                    """
                ),
                row,
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # MongoDB
    try:
        mongodb_manager.connect_sync()
        col = mongodb_manager.get_sync_collection("security_scan_results")
        col.insert_one(row)
    except Exception:
        pass
