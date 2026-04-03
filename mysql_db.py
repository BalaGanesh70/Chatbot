from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import settings

# MySQL Database Configuration
mysql_engine = create_engine(
    settings.mysql_database_url,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=False  # Set to True for SQL debugging
)
MySQLSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=mysql_engine)
MySQLBase = declarative_base()


def get_mysql_db():
    """Dependency to get MySQL database session"""
    db = MySQLSessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_mysql_tables():
    """Create all MySQL tables"""
    MySQLBase.metadata.create_all(bind=mysql_engine)


def drop_mysql_tables():
    """Drop all MySQL tables"""
    MySQLBase.metadata.drop_all(bind=mysql_engine)
