import mysql.connector as mysql
from mysql.connector import Error
import logging
from .config import settings
from .security.password import hash_password

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.connection = None
        self.connect()

    def connect(self):
        try:
            self.connection = mysql.connect(
                host=settings.db_host,
                user=settings.db_user,
                password=settings.db_password,
                database=settings.db_database
            )
            logger.info("Successfully connected to MySQL database")
            cursor = self.connection.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            logger.info(f"Database connection test: {result}")
            cursor.close()
        except Error as e:
            logger.error(f"Error connecting to MySQL database: {e}")
            raise

    def create_tables(self):
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS calls (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    call_sid VARCHAR(255) UNIQUE,
                    from_number VARCHAR(50),
                    to_number VARCHAR(50),
                    direction VARCHAR(20),
                    status VARCHAR(50),
                    start_time DATETIME,
                    end_time DATETIME,
                    duration INT,
                    recording_url TEXT,
                    transcription TEXT,
                    cost DECIMAL(10,2),
                    segments INT,
                    ultravox_cost DECIMAL(10,2),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS service_credentials (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    service_name VARCHAR(255),
                    credentials TEXT,
                    is_connected BOOLEAN DEFAULT FALSE,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255),
                    phone_number VARCHAR(50),
                    email VARCHAR(255),
                    address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS error_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME,
                    path VARCHAR(255),
                    method VARCHAR(10),
                    error_type VARCHAR(100),
                    error_message TEXT,
                    traceback TEXT,
                    headers TEXT,
                    client_ip VARCHAR(45),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Hash the password before storing it
            hashed_password = hash_password('AFINasahbi@-11')
            cursor.execute("""
                INSERT IGNORE INTO users (username, password_hash)
                VALUES (%s, %s)
            """, ('hamza', hashed_password))
            self.connection.commit()
            logger.info("Database tables created successfully")
        except Error as e:
            logger.error(f"Error creating tables: {e}")
            raise
        finally:
            cursor.close()

    async def execute(self, query, params=None):
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params or ())
            result = cursor.fetchall()
            self.connection.commit()
            return result
        except Error as e:
            logger.error(f"Database execution error: {e}")
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def close(self):
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")

db = Database()

def create_tables():
    try:
        db.create_tables()
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        raise
