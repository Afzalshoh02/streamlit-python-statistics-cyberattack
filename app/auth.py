# app/auth.py
import hashlib
from app.database import get_db_connection

def hash_password(password):
    """
    Возвращает SHA-256 хеш от пароля.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def check_credentials(username, password):
    """
    Проверяет, существует ли пользователь с указанным email и паролем.
    """
    db = get_db_connection()
    if not db:
        return False
    cursor = db.cursor()
    hashed_password = hash_password(password)
    query = "SELECT * FROM users WHERE email = %s AND password = %s"
    cursor.execute(query, (username, hashed_password))
    user = cursor.fetchone()
    db.close()
    return user is not None

def register_user(username, password):
    """
    Регистрирует нового пользователя.
    Если пользователь с таким email уже существует – возвращает False.
    """
    db = get_db_connection()
    if not db:
        return False
    cursor = db.cursor()
    hashed_password = hash_password(password)
    
    # Проверка на существование пользователя
    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        db.close()
        return False

    # Регистрация нового пользователя
    query = "INSERT INTO users (email, password) VALUES (%s, %s)"
    cursor.execute(query, (username, hashed_password))
    db.commit()
    db.close()
    return True
