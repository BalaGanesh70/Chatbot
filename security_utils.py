"""
Security utilities for encryption and sensitive data handling
"""
import hashlib
import hmac
import base64
import os
from typing import Optional, List, Tuple
from config import settings

try:
    from presidio_analyzer import AnalyzerEngine
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    AnalyzerEngine = None
    AESGCM = None


def encrypt_value(value: str, role: str) -> str:
    """
    Encrypt a value using role-based encryption key (AES-GCM).
    
    Args:
        value: The value to encrypt
        role: User role for key selection
        
    Returns:
        Base64-encoded encrypted value (nonce + ciphertext)
    """
    if not value or not PRESIDIO_AVAILABLE:
        return value
    
    try:
        role_key = settings.get_role_key(role)
        key = hashlib.sha256(role_key.encode("utf-8")).digest()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("utf-8")
    except Exception as e:
        print(f"⚠️ Encryption failed: {e}")
        return value


def tokenize_value(value: str, role: str) -> str:
    """
    Tokenize a value using role-based tokenization (deterministic hash-based).
    Creates a token that preserves format but is not reversible without the key.
    
    Args:
        value: The value to tokenize
        role: User role for key selection
        
    Returns:
        Token string in format: TOKEN_<hash_prefix>
    """
    if not value:
        return value
    
    try:
        # Use role-based key for tokenization
        role_key = settings.get_role_key(role)
        
        # Create a deterministic token using HMAC-SHA256
        # This ensures same value + role = same token
        token_key = hashlib.sha256((role_key + "token_salt").encode("utf-8")).digest()
        token_hash = hmac.new(token_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        
        # Use first 16 characters of hash as token identifier
        # Format: TOKEN_<hash_prefix> to distinguish from encrypted values
        token_prefix = token_hash[:16].upper()
        return f"TOKEN_{token_prefix}"
    except Exception as e:
        print(f"⚠️ Tokenization failed: {e}")
        return value


def detect_sensitive_entities(text: str, analyzer: Optional[AnalyzerEngine] = None) -> List[Tuple[int, int, str, float]]:
    """
    Detect sensitive entities (PII) in text using Presidio Analyzer.
    
    Args:
        text: Text to analyze
        analyzer: Presidio AnalyzerEngine instance (optional)
        
    Returns:
        List of tuples: (start_index, end_index, entity_type, confidence_score)
    """
    if not text or not analyzer:
        return []
    
    try:
        results = analyzer.analyze(text=text, language="en")
        entities = []
        for result in results:
            if result.score >= 0.5:  # Only high-confidence detections
                entities.append((
                    result.start,
                    result.end,
                    result.entity_type,
                    result.score
                ))
        return entities
    except Exception as e:
        print(f"⚠️ Presidio analysis failed: {e}")
        return []


def encrypt_sensitive_parts_in_text(text: str, role: str, analyzer: Optional[AnalyzerEngine] = None) -> str:
    """
    Detect and encrypt sensitive parts in text for non-HR roles.
    For HR roles, returns text as-is.
    
    Args:
        text: Text that may contain sensitive data
        role: User role
        analyzer: Presidio AnalyzerEngine instance
        
    Returns:
        Text with sensitive parts encrypted (for non-HR) or original text (for HR)
    """
    if not text:
        return text
    
    # HR gets unencrypted data
    role_clean = (role or "").strip().lower()
    if role_clean == "hr":
        return text
    
    # For non-HR roles, encrypt sensitive parts
    if not analyzer or not PRESIDIO_AVAILABLE:
        return text
    
    try:
        # Define sensitive entity types to encrypt (excluding PERSON names)
        sensitive_entity_types = {
            "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE", 
            "US_SSN", "US_PASSPORT", "US_DRIVER_LICENSE", "US_BANK_NUMBER",
            "LOCATION", "ADDRESS", "DATE_TIME", "MEDICAL_LICENSE", "UK_NHS"
        }
        
        # Detect sensitive entities
        entities = detect_sensitive_entities(text, analyzer)
        
        if not entities:
            return text
        
        # Filter to only encrypt specific sensitive types (not PERSON names)
        entities_to_encrypt = [
            (start, end, entity_type, score) 
            for start, end, entity_type, score in entities
            if entity_type in sensitive_entity_types
        ]
        
        if not entities_to_encrypt:
            return text
        
        # Sort entities by start position (descending) to replace from end to start
        # This prevents index shifting issues
        entities_sorted = sorted(entities_to_encrypt, key=lambda x: x[0], reverse=True)
        
        result_text = text
        for start, end, entity_type, score in entities_sorted:
            # Extract the sensitive value
            sensitive_value = text[start:end]
            
            # Encrypt the sensitive value
            encrypted_value = encrypt_value(sensitive_value, role)
            
            # Replace in text
            result_text = result_text[:start] + encrypted_value + result_text[end:]
        
        return result_text
    except Exception as e:
        print(f"⚠️ Failed to encrypt sensitive parts: {e}")
        return text


def encrypt_sensitive_fields_in_rows(headers: list, rows: list, role: str) -> tuple[list, list]:
    """
    Encrypt sensitive fields in database rows while preserving id, full_name, role, and age.
    
    Fields to encrypt: email, phone, address, salary, credit_card, government_id, date_of_birth
    Fields to preserve: id, full_name, role, age, team, office_location
    
    Args:
        headers: List of column names
        rows: List of row data (list of lists/tuples)
        role: User role
        
    Returns:
        Tuple of (headers, encrypted_rows)
    """
    if not rows or not headers:
        return headers, rows
    
    # HR gets unencrypted data
    role_clean = (role or "").strip().lower()
    if role_clean == "hr":
        return headers, rows
    
    # Define fields to encrypt (case-insensitive) - Most sensitive fields
    fields_to_encrypt = {
        "email", "phone", "phone_number", "address_line", 
        "salary", "credit_card", "government_id", "date_of_birth", 
        "dob", "postal_code", "zip"
    }
    
    # Define fields to tokenize (case-insensitive) - Less sensitive but still protected
    fields_to_tokenize = {
        "city", "state", "country", "address"
    }
    
    # Define fields to preserve (case-insensitive)
    fields_to_preserve = {
        "id", "full_name", "name", "role", "age", "team", "office_location"
    }
    
    try:
        # Find indices of fields to encrypt and tokenize
        encrypt_indices = []
        tokenize_indices = []
        
        for idx, header in enumerate(headers):
            header_lower = str(header).lower().strip()
            if header_lower in fields_to_encrypt:
                encrypt_indices.append(idx)
            elif header_lower in fields_to_tokenize:
                tokenize_indices.append(idx)
        
        if not encrypt_indices and not tokenize_indices:
            return headers, rows
        
        # Process each row
        processed_rows = []
        for row in rows:
            processed_row = list(row) if not isinstance(row, list) else row.copy()
            
            # Encrypt sensitive fields
            for idx in encrypt_indices:
                if idx < len(processed_row) and processed_row[idx] is not None:
                    value_str = str(processed_row[idx]).strip()
                    if value_str:
                        processed_row[idx] = encrypt_value(value_str, role)
            
            # Tokenize less sensitive fields
            for idx in tokenize_indices:
                if idx < len(processed_row) and processed_row[idx] is not None:
                    value_str = str(processed_row[idx]).strip()
                    if value_str:
                        processed_row[idx] = tokenize_value(value_str, role)
            
            processed_rows.append(processed_row)
        
        return headers, processed_rows
    except Exception as e:
        print(f"⚠️ Failed to encrypt sensitive fields in rows: {e}")
        return headers, rows

