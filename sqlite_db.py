from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import settings

# SQLite Database Configuration
sqlite_engine = create_engine(
    settings.sqlite_database_url,
    pool_pre_ping=True,
    echo=False  # Set to True for SQL debugging
)
SQLiteSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sqlite_engine)
SQLiteBase = declarative_base()


def get_sqlite_db():
    """Dependency to get SQLite database session"""
    db = SQLiteSessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_sqlite_tables():
    """Create all SQLite tables"""
    SQLiteBase.metadata.create_all(bind=sqlite_engine)


def drop_sqlite_tables():
    """Drop all SQLite tables"""
    SQLiteBase.metadata.drop_all(bind=sqlite_engine)
