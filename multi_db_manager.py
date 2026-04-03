"""
Multi-Database Manager for PrivacyWeave Chatbot
Handles synchronized operations across PostgreSQL, MySQL, SQLite, and MongoDB
"""

from typing import Dict, Any, List, Optional, Union
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
import asyncio
import logging
from contextlib import asynccontextmanager

from db import get_db as get_postgres_db
from mysql_db import get_mysql_db
from sqlite_db import get_sqlite_db
from mongodb_db import get_mongodb, mongodb_manager
from models import (
    User, FAQ, ChatLog, Register, Login, DataLeak, SecurityScanResults
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MultiDatabaseManager:
    """
    Manages operations across multiple databases with synchronization
    """
    
    def __init__(self):
        self.databases = {
            'postgres': 'primary',
            'mysql': 'secondary', 
            'sqlite': 'local',
            'mongodb': 'document'
        }
        self.connection_status = {
            'postgres': False,
            'mysql': False,
            'sqlite': False,
            'mongodb': False
        }
    
    async def initialize_all_connections(self):
        """Initialize connections to all databases"""
        try:
            # Initialize MongoDB connection
            await mongodb_manager.connect()
            mongodb_manager.connect_sync()  # Also create sync connection
            self.connection_status['mongodb'] = True
            logger.info("MongoDB connection initialized")
            
            # Test other database connections
            await self._test_connections()
            
        except Exception as e:
            logger.error(f"Failed to initialize database connections: {e}")
            raise
    
    async def _test_connections(self):
        """Test connections to all databases"""
        # Test PostgreSQL
        try:
            postgres_gen = get_postgres_db()
            postgres_db = next(postgres_gen)
            postgres_db.execute(text("SELECT 1"))
            postgres_db.close()
            self.connection_status['postgres'] = True
            logger.info("PostgreSQL connection verified")
        except Exception as e:
            logger.warning(f"PostgreSQL connection failed: {e}")
        
        # Test MySQL
        try:
            mysql_gen = get_mysql_db()
            mysql_db = next(mysql_gen)
            mysql_db.execute(text("SELECT 1"))
            mysql_db.close()
            self.connection_status['mysql'] = True
            logger.info("MySQL connection verified")
        except Exception as e:
            logger.warning(f"MySQL connection failed: {e}")
        
        # Test SQLite
        try:
            sqlite_gen = get_sqlite_db()
            sqlite_db = next(sqlite_gen)
            sqlite_db.execute(text("SELECT 1"))
            sqlite_db.close()
            self.connection_status['sqlite'] = True
            logger.info("SQLite connection verified")
        except Exception as e:
            logger.warning(f"SQLite connection failed: {e}")
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create user across all databases"""
        results = {}
        
        # PostgreSQL (Primary)
        if self.connection_status['postgres']:
            try:
                postgres_gen = get_postgres_db()
                postgres_db = next(postgres_gen)
                user = User(**user_data)
                postgres_db.add(user)
                postgres_db.commit()
                postgres_db.refresh(user)
                postgres_db.close()
                results['postgres'] = {'success': True, 'id': user.id}
                logger.info(f"User created in PostgreSQL with ID: {user.id}")
            except Exception as e:
                results['postgres'] = {'success': False, 'error': str(e)}
                logger.error(f"PostgreSQL user creation failed: {e}")
        
        # MySQL (Secondary)
        if self.connection_status['mysql']:
            try:
                mysql_gen = get_mysql_db()
                mysql_db = next(mysql_gen)
                # Note: You'll need to create MySQL models similar to PostgreSQL models
                # For now, we'll use raw SQL
                mysql_db.execute(text("""
                    INSERT INTO users (full_name, role, age, email, team, office_location, 
                                     salary, address_line, city, state, country, postal_code, created_at)
                    VALUES (:full_name, :role, :age, :email, :team, :office_location,
                            :salary, :address_line, :city, :state, :country, :postal_code, :created_at)
                """), {**user_data, 'created_at': datetime.utcnow()})
                mysql_db.commit()
                mysql_db.close()
                results['mysql'] = {'success': True}
                logger.info("User created in MySQL")
            except Exception as e:
                results['mysql'] = {'success': False, 'error': str(e)}
                logger.error(f"MySQL user creation failed: {e}")
        
        # SQLite (Local)
        if self.connection_status['sqlite']:
            try:
                sqlite_gen = get_sqlite_db()
                sqlite_db = next(sqlite_gen)
                sqlite_db.execute(text("""
                    INSERT INTO users (full_name, role, age, email, team, office_location,
                                     salary, address_line, city, state, country, postal_code, created_at)
                    VALUES (:full_name, :role, :age, :email, :team, :office_location,
                            :salary, :address_line, :city, :state, :country, :postal_code, :created_at)
                """), {**user_data, 'created_at': datetime.utcnow()})
                sqlite_db.commit()
                sqlite_db.close()
                results['sqlite'] = {'success': True}
                logger.info("User created in SQLite")
            except Exception as e:
                results['sqlite'] = {'success': False, 'error': str(e)}
                logger.error(f"SQLite user creation failed: {e}")
        
        # MongoDB (Document)
        if self.connection_status['mongodb']:
            try:
                users_collection = await get_mongodb()
                users_collection = users_collection.users
                user_data['created_at'] = datetime.utcnow()
                result = await users_collection.insert_one(user_data)
                results['mongodb'] = {'success': True, 'id': str(result.inserted_id)}
                logger.info(f"User created in MongoDB with ID: {result.inserted_id}")
            except Exception as e:
                results['mongodb'] = {'success': False, 'error': str(e)}
                logger.error(f"MongoDB user creation failed: {e}")
        
        return results
    
    async def create_chat_log(self, chat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create chat log across all databases"""
        results = {}
        
        # PostgreSQL (Primary)
        if self.connection_status['postgres']:
            try:
                postgres_gen = get_postgres_db()
                postgres_db = next(postgres_gen)
                chat_log = ChatLog(**chat_data)
                postgres_db.add(chat_log)
                postgres_db.commit()
                postgres_db.refresh(chat_log)
                postgres_db.close()
                results['postgres'] = {'success': True, 'id': chat_log.id}
                logger.info(f"Chat log created in PostgreSQL with ID: {chat_log.id}")
            except Exception as e:
                results['postgres'] = {'success': False, 'error': str(e)}
                logger.error(f"PostgreSQL chat log creation failed: {e}")
        
        # MongoDB (Document) - Store as document for better querying
        if self.connection_status['mongodb']:
            try:
                chat_logs_collection = await get_mongodb()
                chat_logs_collection = chat_logs_collection.chat_logs
                chat_data['created_at'] = datetime.utcnow()
                result = await chat_logs_collection.insert_one(chat_data)
                results['mongodb'] = {'success': True, 'id': str(result.inserted_id)}
                logger.info(f"Chat log created in MongoDB with ID: {result.inserted_id}")
            except Exception as e:
                results['mongodb'] = {'success': False, 'error': str(e)}
                logger.error(f"MongoDB chat log creation failed: {e}")
        
        # MySQL and SQLite (if needed for backup)
        for db_name in ['mysql', 'sqlite']:
            if self.connection_status[db_name]:
                try:
                    db_gen = get_mysql_db() if db_name == 'mysql' else get_sqlite_db()
                    db = next(db_gen)
                    db.execute(text("""
                        INSERT INTO chat_logs (user_role, user_name, message, response, 
                                             sensitivity, expires_at, created_at)
                        VALUES (:user_role, :user_name, :message, :response,
                                :sensitivity, :expires_at, :created_at)
                    """), {**chat_data, 'created_at': datetime.utcnow()})
                    db.commit()
                    db.close()
                    results[db_name] = {'success': True}
                    logger.info(f"Chat log created in {db_name}")
                except Exception as e:
                    results[db_name] = {'success': False, 'error': str(e)}
                    logger.error(f"{db_name} chat log creation failed: {e}")
        
        return results
    
    async def create_data_leak(self, leak_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create data leak record across all databases"""
        results = {}
        
        # PostgreSQL (Primary)
        if self.connection_status['postgres']:
            try:
                postgres_gen = get_postgres_db()
                postgres_db = next(postgres_gen)
                data_leak = DataLeak(**leak_data)
                postgres_db.add(data_leak)
                postgres_db.commit()
                postgres_db.refresh(data_leak)
                postgres_db.close()
                results['postgres'] = {'success': True, 'id': data_leak.id}
                logger.info(f"Data leak created in PostgreSQL with ID: {data_leak.id}")
            except Exception as e:
                results['postgres'] = {'success': False, 'error': str(e)}
                logger.error(f"PostgreSQL data leak creation failed: {e}")
        
        # MongoDB (Document) - Store for analytics
        if self.connection_status['mongodb']:
            try:
                leaks_collection = await get_mongodb()
                leaks_collection = leaks_collection.data_leaks
                leak_data['created_at'] = datetime.utcnow()
                result = await leaks_collection.insert_one(leak_data)
                results['mongodb'] = {'success': True, 'id': str(result.inserted_id)}
                logger.info(f"Data leak created in MongoDB with ID: {result.inserted_id}")
            except Exception as e:
                results['mongodb'] = {'success': False, 'error': str(e)}
                logger.error(f"MongoDB data leak creation failed: {e}")
        
        return results
    
    async def get_connection_status(self) -> Dict[str, bool]:
        """Get status of all database connections"""
        return self.connection_status.copy()
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all databases"""
        health_status = {}
        
        for db_name in self.databases.keys():
            try:
                if db_name == 'postgres':
                    postgres_gen = get_postgres_db()
                    postgres_db = next(postgres_gen)
                    postgres_db.execute(text("SELECT 1"))
                    postgres_db.close()
                    health_status[db_name] = {'status': 'healthy', 'response_time': 'fast'}
                
                elif db_name == 'mysql':
                    mysql_gen = get_mysql_db()
                    mysql_db = next(mysql_gen)
                    mysql_db.execute(text("SELECT 1"))
                    mysql_db.close()
                    health_status[db_name] = {'status': 'healthy', 'response_time': 'fast'}
                
                elif db_name == 'sqlite':
                    sqlite_gen = get_sqlite_db()
                    sqlite_db = next(sqlite_gen)
                    sqlite_db.execute(text("SELECT 1"))
                    sqlite_db.close()
                    health_status[db_name] = {'status': 'healthy', 'response_time': 'fast'}
                
                elif db_name == 'mongodb':
                    await mongodb_manager.client.admin.command('ping')
                    health_status[db_name] = {'status': 'healthy', 'response_time': 'fast'}
                
            except Exception as e:
                health_status[db_name] = {'status': 'unhealthy', 'error': str(e)}
        
        return health_status
    
    async def cleanup(self):
        """Cleanup all database connections"""
        try:
            await mongodb_manager.disconnect()
            logger.info("All database connections cleaned up")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

# Global instance
multi_db_manager = MultiDatabaseManager()
