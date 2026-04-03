import os
from dataclasses import dataclass, field
from dotenv import load_dotenv


load_dotenv()


@dataclass
class Settings:
    # PostgreSQL Configuration (Primary Database)
    db_host: str = os.getenv("DB_HOST", "localhost")
    db_port: int = int(os.getenv("DB_PORT", "5432"))
    db_name: str = os.getenv("DB_NAME", "chatbot_db")
    db_user: str = os.getenv("DB_USER", "postgres")
    db_password: str = os.getenv("DB_PASSWORD", "postgres")
    database_url: str = os.getenv("DATABASE_URL", "")
    
    # MySQL Configuration (Secondary Database)
    mysql_host: str = os.getenv("MYSQL_HOST", "localhost")
    mysql_port: int = int(os.getenv("MYSQL_PORT", "3306"))
    mysql_db: str = os.getenv("MYSQL_DB", "privacyweave_mysql")
    mysql_user: str = os.getenv("MYSQL_USER", "privacyweave_user")
    mysql_password: str = os.getenv("MYSQL_PASSWORD", "privacyweave_pass123")
    
    # SQLite Configuration (Local Database)
    sqlite_path: str = os.getenv("SQLITE_PATH", "privacyweave_data.db")
    
    # MongoDB Configuration (Document Database)
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://privacyweave_user:privacyweave_pass123@localhost:27017/privacyweave_mongo?authSource=privacyweave_mongo")
    mongo_db: str = os.getenv("MONGO_DB", "privacyweave_mongo")
    
    # API Configuration
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    allowed_origins: list[str] = field(default_factory=list)
    
    # OpenAI Configuration
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    # Security Configuration
    encryption_secret: str = os.getenv("ENCRYPTION_SECRET", "dev-secret-change-me")
    role_key_visitor: str = os.getenv("ROLE_KEY_VISITOR", "")
    role_key_applicant: str = os.getenv("ROLE_KEY_APPLICANT", "")
    role_key_intern: str = os.getenv("ROLE_KEY_INTERN", "")
    role_key_senior_engineer: str = os.getenv("ROLE_KEY_SENIOR_ENGINEER", "")
    role_key_tech_lead: str = os.getenv("ROLE_KEY_TECH_LEAD", "")
    role_key_hr: str = os.getenv("ROLE_KEY_HR", "")

    def __post_init__(self) -> None:
        if not self.database_url:
            self.database_url = (
                f"postgresql+psycopg2://{self.db_user}:{self.db_password}"
                f"@{self.db_host}:{self.db_port}/{self.db_name}"
            )
        if not self.allowed_origins:
            self.allowed_origins = (
                os.getenv("ALLOWED_ORIGINS", "http://localhost:8501, http://127.0.0.1:8501")
                .replace(" ", "")
                .split(",")
            )
    
    @property
    def mysql_database_url(self) -> str:
        """Generate MySQL database URL"""
        return f"mysql+pymysql://{self.mysql_user}:{self.mysql_password}@{self.mysql_host}:{self.mysql_port}/{self.mysql_db}"
    
    @property
    def sqlite_database_url(self) -> str:
        """Generate SQLite database URL"""
        return f"sqlite:///{self.sqlite_path}"

    def get_role_key(self, role: str) -> str:
        role_lc = (role or "").strip().lower()
        if role_lc == "visitor":
            return self.role_key_visitor or self.encryption_secret
        if role_lc == "applicant":
            return self.role_key_applicant or self.encryption_secret
        if role_lc == "intern":
            return self.role_key_intern or self.encryption_secret
        if role_lc == "senior engineer":
            return self.role_key_senior_engineer or self.encryption_secret
        if role_lc == "tech lead":
            return self.role_key_tech_lead or self.encryption_secret
        if role_lc == "hr":
            return self.role_key_hr or self.encryption_secret
        return self.encryption_secret


settings = Settings()


