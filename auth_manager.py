"""
Authentication Manager Module
Handles user authentication, registration, and password management
"""

import bcrypt
import re
from typing import Tuple, Optional
from db_manager import DatabaseManager

class AuthManager:
    """Manages user authentication and registration"""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize authentication manager
        
        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid: bool, message: str)
        """
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        
        if len(password) > 128:
            return False, "Password is too long (max 128 characters)"
        
        # Check for at least one letter and one number
        if not re.search(r'[A-Za-z]', password):
            return False, "Password must contain at least one letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        return True, "Password is strong"
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password: Plain text password
            password_hash: Stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def register_user(self, username: str, password: str, email: Optional[str] = None) -> Tuple[bool, str]:
        """
        Register a new user
        
        Args:
            username: Desired username
            password: Plain text password
            email: Optional email address
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Validate username
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username) > 50:
            return False, "Username is too long (max 50 characters)"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        # Validate password
        is_valid, message = self.validate_password_strength(password)
        if not is_valid:
            return False, message
        
        # Validate email if provided
        if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False, "Invalid email format"
        
        # Hash password and store user
        password_hash = self.hash_password(password)
        return self.db.add_user(username, password_hash, email)
    
    def login_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate a user
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not username or not password:
            return False, "Username and password are required"
        
        # Get user from database
        user = self.db.get_user(username)
        
        if not user:
            return False, "Invalid username or password"
        
        # user tuple: (id, username, password_hash, email, created_at)
        password_hash = user[2]
        
        # Verify password
        if self.verify_password(password, password_hash):
            return True, f"Welcome back, {username}!"
        else:
            return False, "Invalid username or password"
