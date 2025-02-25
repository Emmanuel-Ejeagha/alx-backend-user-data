#!/usr/bin/env python3

"""Database model for our project"""
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

Base = declarative_base()


class User(Base):
    """The user model which will be mapped to a table in SQL"""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    seesion_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)
