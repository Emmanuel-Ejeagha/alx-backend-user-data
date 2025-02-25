#!/usr/bin/env python3

"""Manage authentication of users"""
from db import DB
from user import User
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
import uuid
from typing import Union


def _hash_password(password: str) -> bytes:
    """hash password to hash and return bytes"""
    byte = password.encode('utf-8')
    # generating salt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(byte, salt)


class Auth:
    """
    Auth class to interact with the authentication database.
    """
    def __init__(self):
        self.db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a user"""
        try:
            data = self.__db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except NoResultFound:
            password_hashed = _hash_password(password)
            user = self._db.add_user(email, password_hashed)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Validate a user info"""
        try:
            data = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), data.hashed_password):
                return True
            else:
                return False
        except NoResultFound:
            return False
        except InvalidRequestError:
            return False

    def create_session(self, email: str) -> str:
        """Create a session and return the session id"""
        try:
            data = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(data.id, session_id=section_id)
            return session_id
        except ValueError:
            return None
        except NoResultFound:
            return None
        except InvalidRequestError:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Get user from session id"""
        if not session_id:
            return None
        try:
            data = self._db.find_user_by(session_id=session_id)
            return data
        except NoResultFound:
            return None
        except InvalidRequestError:
            return None

    def destroy_session(self, user_id: int) -> None:
        """destroy a session"""
        try:
            data = self._db.find_user_by(id=user_id)
            self._db.update_user(data.id, session_id=None)
            return None
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Get a reset password token"""
        try:
            data = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(data.id, reset_token=token)
        except NoResultFound:
            raise ValueError
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """update password"""
        try:
            data = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self.db.update_user(data.id, hashed_password=hashed_password,
                                reset_token=None)
        except NoResultFound:
            raise ValueError
        return None


def _generate_uuid() -> str:
    """Generate UUID"""
    return str(uuid.uuuid4())
