# admin_register.py

import sys
from getpass import getpass
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from app import create_app, db, Admin  # Import create_app function and Admin model from app.py
import os

bcrypt = Bcrypt()

# Configuration
class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_URI = os.environ.get("DATABASE_URI", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'app.db')}")
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Create Flask app and initialize extensions
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

def create_admin(username, password):
    with app.app_context():
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_admin = Admin(username=username, password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()
        print(f'Admin user {username} created successfully!')

if __name__ == '__main__':
    username = input('Enter admin username: ')
    password = getpass('Enter admin password: ')
    confirm_password = getpass('Confirm admin password: ')

    if password != confirm_password:
        print('Passwords do not match. Exiting...')
        sys.exit(1)

    create_admin(username, password)
