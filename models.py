from sqlalchemy import Column, Integer, String
from database import Base
from sqlalchemy import DateTime
import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    email = Column(String)
    role = Column(String, default="user")


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True)
    revoked_at = Column(DateTime, default=datetime.datetime.utcnow)
