from functools import wraps
import binascii
import os

from sqlalchemy import Column, String
from flask import request
from flask_restful import Resource, abort
from passlib.hash import argon2
from marshmallow import Schema, fields
from flask_login import login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeSerializer

def authorization(roles_permissions):
    def authorization_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if hasattr(current_user, 'role'):
                role = current_user.role
            else:
                role = None

            if role and role in roles_permissions:
                if request.method in roles_permissions[role]:
                    return func(*args, **kwargs)

            abort(403)
        return wrapper
    return authorization_decorator

class CSRF(object):
    header = 'X-CSRF'

    def __init__(self, csrf_secret=None):
        csrf_secret = csrf_secret or os.getenv('CSRF_SECRET', None)
        self.csrf_signer = URLSafeSerializer(csrf_secret)

    def generate_token(self):
        return self.csrf_signer.dumps(binascii.hexlify(os.urandom(32)).decode('utf-8'))

    def csrf_check(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method in ['GET','HEAD','OPTIONS'] or \
                (hasattr(current_user, 'is_api') and current_user.is_api):
                return func(*args, **kwargs)

            ## check for X-CSRF header and check signature
            try:
                self.csrf_signer.loads(request.headers[self.header])
            except:
                abort(401)

            return func(*args, **kwargs)
        return wrapper

class UserAuthMixin(object):
    username = Column(String, index=True, nullable=False)
    hashed_password = Column(String)

    @property
    def password(self):
        raise Exception('Cannot get password from User.')

    def get_password_hash(self, password):
        return argon2.using(rounds=4).hash(password)

    @password.setter
    def password(self, password):
        if password is None:
            self.hashed_password = None
        else:
            self.hashed_password = self.get_password_hash(password)

    def verify_password(self, input_password):
        if not self.hashed_password or not input_password:
            return False

        return argon2.verify(input_password, self.hashed_password)

class SessionSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

session_schema = SessionSchema()

class SessionResource(Resource):
    def post(self):
        raw_body = request.json
        session_load = session_schema.load(raw_body or {})

        if session_load.errors:
            abort(400, errors=session_load.errors)

        session = session_load.data

        user = self.session.query(self.User)\
                    .filter(self.User.username == session['username'])\
                    .first()

        if not user:
            abort(401, errors=['Not Authorized'])

        password_matches = user.verify_password(session['password'])
        if not password_matches:
            abort(401, errors=['Not Authorized'])

        login_user(user)

        response_body = {'csrf_token': self.csrf.generate_token()}
        return response_body

    @login_required
    def get(self):
        return None, 204

    def delete(self):
        logout_user()

        return None, 204
