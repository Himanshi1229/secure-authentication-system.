import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_jwt_secret_key_change_in_production')
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL', 
        'postgresql://postgres:postgres@localhost:5432/secure_auth_db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
  
