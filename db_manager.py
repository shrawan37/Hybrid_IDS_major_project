"""
Database Manager Module
Handles SQLite database operations for user management
"""

import sqlite3
import os
from typing import Optional, Tuple, List

class DatabaseManager:
    """Manages SQLite database operations for user authentication"""
    
    def __init__(self, db_path: str = "users.db"):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create users table if it doesn't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_user(self, username: str, password_hash: str, email: Optional[str] = None) -> Tuple[bool, str]:
        """
        Add a new user to the database
        
        Args:
            username: Unique username
            password_hash: Hashed password
            email: Optional email address
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                (username, password_hash, email)
            )
            
            conn.commit()
            conn.close()
            return True, "User created successfully"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, f"Database error: {str(e)}"
    
    def get_user(self, username: str) -> Optional[Tuple]:
        """
        Retrieve user information by username
        
        Args:
            username: Username to search for
            
        Returns:
            Tuple of (id, username, password_hash, email, created_at) or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, username, password_hash, email, created_at FROM users WHERE username = ?',
            (username,)
        )
        
        user = cursor.fetchone()
        conn.close()
        
        return user
    
    def get_all_users(self) -> List[Tuple]:
        """
        Get all users (for admin purposes)
        
        Returns:
            List of user tuples
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, email, created_at FROM users')
        users = cursor.fetchall()
        
        conn.close()
        return users
    
    def delete_user(self, username: str) -> Tuple[bool, str]:
        """
        Delete a user from the database
        
        Args:
            username: Username to delete
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            
            if cursor.rowcount == 0:
                conn.close()
                return False, "User not found"
            
            conn.commit()
            conn.close()
            return True, "User deleted successfully"
        except Exception as e:
            return False, f"Database error: {str(e)}"
