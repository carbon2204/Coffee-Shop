import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key'
    # Обратите внимание на формат URI для PostgreSQL:
    # 'postgresql://<username>:<password>@<host>/<database_name>'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:3752@localhost/coffee_shop'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
