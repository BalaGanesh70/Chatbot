from pydantic import BaseModel
from pydantic import ConfigDict
from typing import Optional
from datetime import datetime


class ChatRequest(BaseModel):
    message: str
    role: str  
    name: Optional[str] = None
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    reply: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    main_id_password: str
    role: str  
    date_of_birth: Optional[str] = None
    government_id: Optional[str] = None


class RegisterResponse(BaseModel):
    message: str
    user_id: int


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    message: str
    name: str
    role: str


class FAQCreate(BaseModel):
    category: str
    question: str
    answer: str
    visibility: str = "public"


class FAQOut(BaseModel):
    id: int
    category: str
    question: str
    answer: str
    visibility: str

    
    model_config = ConfigDict(from_attributes=True)


class DataLeakOut(BaseModel):
    id: int
    session_id: Optional[str] = None
    hr_name: Optional[str] = None
    question: str
    answer_preview: str
    category: Optional[str] = None
    created_at: datetime
    summary: str
    
    # Enhanced leak detection fields for dashboard
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    user_role: Optional[str] = None
    target_role: Optional[str] = None
    leak_type: Optional[str] = None
    external_calls: Optional[int] = None
    risky_flows: Optional[int] = None


class SecurityScanResultsOut(BaseModel):
    id: int
    fake_names_count: int
    medical_records_count: int
    api_keys_count: int
    jailbreak_attempts_count: int
    pii_phi_secrets_count: int
    risky_flows_count: int
    external_calls_count: int
    resistance_percentage: int
    leaked_records_count: int
    scan_date: datetime
    hr_user: Optional[str] = None
    session_id: Optional[str] = None
    is_latest: int
    
    model_config = ConfigDict(from_attributes=True)


class ChatHistorySearchRequest(BaseModel):
    role: str
    search_query: Optional[str] = None


class ChatHistoryCSVExportRequest(BaseModel):
    role: str
    search_query: Optional[str] = None
