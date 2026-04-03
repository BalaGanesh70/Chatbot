"""
Database Initialization Script for PrivacyWeave Chatbot
Creates tables in all configured databases
"""

import asyncio
import logging
from sqlalchemy import text

from db import engine, Base
from mysql_db import mysql_engine, MySQLBase, create_mysql_tables
from sqlite_db import sqlite_engine, SQLiteBase, create_sqlite_tables
from mongodb_db import mongodb_manager
from models import *  # Import all PostgreSQL models
from mysql_models import *  # Import all MySQL models
from sqlite_models import *  # Import all SQLite models

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_postgresql():
    """Initialize PostgreSQL database"""
    try:
        logger.info("Initializing PostgreSQL database...")
        Base.metadata.create_all(bind=engine)
        logger.info("PostgreSQL database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL: {e}")
        return False

def init_mysql():
    """Initialize MySQL database"""
    try:
        logger.info("Initializing MySQL database...")
        create_mysql_tables()
        logger.info("MySQL database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize MySQL: {e}")
        return False

def init_sqlite():
    """Initialize SQLite database"""
    try:
        logger.info("Initializing SQLite database...")
        create_sqlite_tables()
        logger.info("SQLite database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize SQLite: {e}")
        return False

async def init_mongodb():
    """Initialize MongoDB database"""
    try:
        logger.info("Initializing MongoDB database...")
        await mongodb_manager.connect()
        mongodb_manager.connect_sync()
        await mongodb_manager.create_indexes()
        logger.info("MongoDB database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize MongoDB: {e}")
        return False

async def init_all_databases():
    """Initialize all databases"""
    logger.info("Starting database initialization...")
    
    results = {
        'postgresql': False,
        'mysql': False,
        'sqlite': False,
        'mongodb': False
    }
    
    # Initialize PostgreSQL
    results['postgresql'] = await init_postgresql()
    
    # Initialize MySQL
    results['mysql'] = init_mysql()
    
    # Initialize SQLite
    results['sqlite'] = init_sqlite()
    
    # Initialize MongoDB
    results['mongodb'] = await init_mongodb()
    
    # Summary
    logger.info("Database initialization summary:")
    for db_name, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        logger.info(f"  {db_name.upper()}: {status}")
    
    successful_dbs = sum(results.values())
    total_dbs = len(results)
    logger.info(f"Successfully initialized {successful_dbs}/{total_dbs} databases")
    
    return results

async def test_connections():
    """Test connections to all databases"""
    logger.info("Testing database connections...")
    
    # Test PostgreSQL
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("✓ PostgreSQL connection successful")
    except Exception as e:
        logger.error(f"✗ PostgreSQL connection failed: {e}")
    
    # Test MySQL
    try:
        with mysql_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("✓ MySQL connection successful")
    except Exception as e:
        logger.error(f"✗ MySQL connection failed: {e}")
    
    # Test SQLite
    try:
        with sqlite_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("✓ SQLite connection successful")
    except Exception as e:
        logger.error(f"✗ SQLite connection failed: {e}")
    
    # Test MongoDB
    try:
        await mongodb_manager.client.admin.command('ping')
        logger.info("✓ MongoDB connection successful")
    except Exception as e:
        logger.error(f"✗ MongoDB connection failed: {e}")

if __name__ == "__main__":
    async def main():
        await test_connections()
        await init_all_databases()
    
    asyncio.run(main())
