from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
from config import settings
import asyncio
from typing import Optional

# MongoDB Database Configuration
class MongoDBManager:
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.sync_client: Optional[MongoClient] = None
        self.database = None
        self.sync_database = None
    
    async def connect(self):
        """Connect to MongoDB asynchronously"""
        try:
            self.client = AsyncIOMotorClient(settings.mongo_uri)
            self.database = self.client[settings.mongo_db]
            # Test the connection
            await self.client.admin.command('ping')
            print(f"Connected to MongoDB: {settings.mongo_db}")
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise
    
    def connect_sync(self):
        """Connect to MongoDB synchronously"""
        try:
            self.sync_client = MongoClient(settings.mongo_uri)
            self.sync_database = self.sync_client[settings.mongo_db]
            # Test the connection
            self.sync_client.admin.command('ping')
            print(f"Connected to MongoDB (sync): {settings.mongo_db}")
        except Exception as e:
            print(f"Failed to connect to MongoDB (sync): {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from MongoDB"""
        if self.client is not None:
            self.client.close()
        if self.sync_client is not None:
            self.sync_client.close()
    
    def get_collection(self, collection_name: str):
        """Get a collection from the database"""
        if self.database is None:
            raise Exception("MongoDB not connected. Call connect() first.")
        return self.database[collection_name]
    
    def get_sync_collection(self, collection_name: str):
        """Get a collection from the database (synchronous)"""
        if self.sync_database is None:
            raise Exception("MongoDB not connected. Call connect_sync() first.")
        return self.sync_database[collection_name]
    
    async def create_indexes(self):
        """Create common indexes for better performance"""
        collections = [
            'users', 'faqs', 'chat_logs', 'register', 'login', 
            'data_leaks', 'security_scan_results'
        ]
        
        for collection_name in collections:
            collection = self.get_collection(collection_name)
            
            # Create common indexes
            if collection_name == 'users':
                await collection.create_index("email", unique=True)
                await collection.create_index("created_at")
            elif collection_name == 'chat_logs':
                await collection.create_index("created_at")
                await collection.create_index("user_role")
            elif collection_name == 'data_leaks':
                await collection.create_index("created_at")
                await collection.create_index("risk_level")
            elif collection_name == 'register':
                await collection.create_index("username", unique=True)
                await collection.create_index("email_fp", unique=True)
            elif collection_name == 'login':
                await collection.create_index("username")
                await collection.create_index("created_at")
    
    async def drop_all_collections(self):
        """Drop all collections (use with caution)"""
        if self.database is None:
            raise Exception("MongoDB not connected. Call connect() first.")
        
        collections = await self.database.list_collection_names()
        for collection_name in collections:
            await self.database.drop_collection(collection_name)
            print(f"Dropped collection: {collection_name}")

# Global MongoDB manager instance
mongodb_manager = MongoDBManager()

# Dependency functions
async def get_mongodb():
    """Dependency to get MongoDB database"""
    if mongodb_manager.database is None:
        await mongodb_manager.connect()
    return mongodb_manager.database

def get_mongodb_sync():
    """Dependency to get MongoDB database (synchronous)"""
    if mongodb_manager.sync_database is None:
        mongodb_manager.connect_sync()
    return mongodb_manager.sync_database

# Collection getters
async def get_users_collection():
    """Get users collection"""
    db = await get_mongodb()
    return db.users

async def get_faqs_collection():
    """Get FAQs collection"""
    db = await get_mongodb()
    return db.faqs

async def get_chat_logs_collection():
    """Get chat logs collection"""
    db = await get_mongodb()
    return db.chat_logs

async def get_register_collection():
    """Get register collection"""
    db = await get_mongodb()
    return db.register

async def get_login_collection():
    """Get login collection"""
    db = await get_mongodb()
    return db.login

async def get_data_leaks_collection():
    """Get data leaks collection"""
    db = await get_mongodb()
    return db.data_leaks

async def get_security_scan_results_collection():
    """Get security scan results collection"""
    db = await get_mongodb()
    return db.security_scan_results
