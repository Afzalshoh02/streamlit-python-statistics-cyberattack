import MySQLdb

def create_db_and_table():
    """Создание базы данных и таблицы, если они не существуют"""
    # Подключение к MySQL серверу, без указания базы данных
    db = MySQLdb.connect(
        host='127.0.0.1',
        user='root',
        passwd='root',
        port=3306
    )
    
    cursor = db.cursor()

    # Создаем базу данных, если она не существует
    cursor.execute("CREATE DATABASE IF NOT EXISTS cybersecurity_db")

    # Выбираем базу данных
    db.select_db('cybersecurity_db')

    # Создаем таблицу, если она не существует
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            is_admin INT DEFAULT 0
        )
    """)

    db.commit()
    db.close()

def get_db_connection():
    """Подключение к базе данных"""
    
    create_db_and_table()

    
    db = MySQLdb.connect(
        host='127.0.0.1',
        user='root',
        passwd='root',
        db='cybersecurity_db',
        port=3306
    )
    return db
