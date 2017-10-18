from functools import wraps
import binascii
import os
import re
import uuid
import json
from datetime import datetime, timedelta

from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, Index, func
from sqlalchemy.dialects.postgresql import INET, UUID, ARRAY
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import validates
from sqlalchemy.event import listens_for
from flask import request, current_app
from flask_restful import Resource, abort
from passlib.hash import argon2
from marshmallow import Schema, fields
from flask_login import LoginManager, login_required, current_user
from cryptography.fernet import Fernet
import dateutil.parser

def authorization(roles_permissions):
    def authorization_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if current_user and hasattr(current_user, 'role'):
                role = current_user.role
            else:
                role = None

            if role and role in roles_permissions:
                if request.method in roles_permissions[role]:
                    return func(*args, **kwargs)

            abort(403)
        return wrapper
    return authorization_decorator

def csrf_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.method in ['GET','HEAD','OPTIONS'] or \
            (hasattr(current_user, 'token') and current_user.token.type != 'session'):
            return func(*args, **kwargs)

        if 'X-Requested-With' in request.headers:
            return func(*args, **kwargs)

        abort(401)
    return wrapper

def verify_token_fernet(fernet, raw_input_token):
    try:
        input_token = re.compile('^[0-9a-f]{8}:').sub('', raw_input_token, count=1)
        data = json.loads(fernet.decrypt(input_token.encode('utf-8')).decode('utf-8'))
        expires_at = dateutil.parser.parse(data['expires_at'])
    except:
        return None

    if expires_at <= datetime.utcnow():
        return None

    return data

class TokenMixin(object):
    """
    Mix with a model base class
    """

    __tablename__ = 'tokens'

    # instance of cryptography.fernet.Fernet
    fernet = None

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(Enum('session', 'token', 'refresh_token', name='token_type'), nullable=False)
    @declared_attr
    def user_id(cls):
        return Column(Integer, ForeignKey('users.id'), index=True)
    scopes = Column(ARRAY(String))
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, index=True)
    ip = Column(INET, nullable=False)
    user_agent = Column(String)
    created_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now())
    updated_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now(),
                        onupdate=func.now())

    @validates('scopes')
    def validate_scopes(self, key, scopes):
        if self.type == 'session' and self.type != None:
            raise Exception('Session tokens do not have scopes')

        if (self.type == 'token' or self.type == 'refresh_token') and \
           (scopes == None or len(scopes) == 0):
            raise Exception('Types `token` and `refresh_token` require `scopes`')

        return scopes

    @property
    def token(self):
        token_str = self.fernet.encrypt(json.dumps({
            'id': str(self.id),
            'user_id': self.user_id,
            'expires_at': self.expires_at.isoformat()
        }).encode('utf-8')).decode('utf-8')

        return str(self.id)[:8] + ':' + token_str # adding first 8 of ID to help id tokens

    @classmethod
    def verify_token(cls, session, raw_input_token):
        data = verify_token_fernet(cls.fernet, raw_input_token)

        if data == None:
            return None

        token = session.query(cls) \
            .filter(cls.id == data['id'],
                    cls.user_id == data['user_id'],
                    cls.revoked_at == None,
                    cls.expires_at > func.now()) \
            .one_or_none()

        if token:
            return token

        return None

class UserAuthMixin(object):
    hashed_password = Column(String)

    ### Usage create an email column similar to
    # email = Column(String, unique=True, nullable=False)

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

class AuthLogEntryMixin(object):
    __tablename__ = 'auth_log'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(Enum(
                'failed_login_attempt',
                'failed_password_recovery_attempt',
                'login',
                'password_change',
                'password_recovery',
                name='auth_log_types'), index=True)
    email = Column(String, index=True, nullable=False)
    @declared_attr
    def user_id(cls):
        return Column(Integer, ForeignKey('users.id'), index=True)
    ip = Column(INET, nullable=True)
    timestamp = Column(DateTime, index=True, nullable=False, default=func.now())
    user_agent = Column(String)

    @classmethod
    def build_indexes(cls):
        Index('idx_ip', cls.ip, postgresql_using='gist', postgresql_ops={'ip': 'inet_ops'})

@listens_for(AuthLogEntryMixin, 'instrument_class', propagate=True)
def receive_mapper_configured(mapper, class_):
    class_.build_indexes()

class SessionSchema(Schema):
    email = fields.Str(required=True)
    password = fields.Str(required=True)

session_schema = SessionSchema()

def get_ip(number_of_proxies):
    if 'X-Forwarded-For' in request.headers:
        path = request.headers.getlist("X-Forwarded-For")[0].rpartition(' ')
        if len(path) != number_of_proxies:
            abort(401)
        return path[-1]
    if number_of_proxies > 0:
        abort(401)
    return request.remote_addr

throttle_login_sql = '''
SELECT
    SUM(1) AS global_attempt_count,
    SUM(CASE WHEN ip = :login_attempt_ip THEN 1 ELSE 0 END) AS ip_attempt_count,
    SUM(CASE WHEN ip << NETWORK(SET_MASKLEN(:login_attempt_ip, 24)) THEN 1 ELSE 0 END) AS ip_block_attempt_count,
    SUM(CASE WHEN email = :email AND ip = :login_attempt_ip THEN 1 ELSE 0 END) AS email_ip_attempt_count,
    SUM(CASE WHEN email = :email AND ip << NETWORK(SET_MASKLEN(:login_attempt_ip, 24)) THEN 1 ELSE 0 END) AS email_network_attempt_count
FROM auth_log
WHERE type = 'failed_login_attempt' AND timestamp >= (:now - (:period * INTERVAL '1 second'))
'''

class SessionResource(Resource):
    token_model = None
    cookie_name = 'session'
    cookie_domain = None
    cookie_path = None
    secure_cookie = False
    session_timeout = timedelta(hours=12)
    number_of_proxies = 0
    auth_log_entry_model = None
    now = None
    login_attempt_period = 900 # 15 minutes
    max_global_login_attempts = 500
    max_login_attempts_per_ip = 100
    max_login_attempts_per_ip_block = 200
    max_login_attempts_per_email_ip = 5
    max_login_attempts_per_email_network = 10
    max_active_sessions_per_user = 10

    def get_cookie(self, token, expires_at):
        domain = ''
        if self.cookie_domain:
            domain = 'Domain={}; '.format(self.domain)

        path = ''
        if self.cookie_path:
            path = 'Path={}; '.format(self.path)

        secure = ''
        if self.secure_cookie:
            secure = 'Secure; '

        return '{}={}; Expires={}; {}{}{}HttpOnly'.format(
            self.cookie_name,
            token,
            expires_at,
            domain,
            path,
            secure)

    def session_token(self, user, ip):
        token = self.token_model(
            type='session',
            user_id=user.id,
            expires_at=datetime.utcnow() + self.session_timeout,
            ip=ip,
            user_agent=request.user_agent.string)
        self.session.add(token)
        self.session.commit()

        expires_at = token.expires_at.strftime('%a, %d %b %Y %H:%M:%S GMT')

        return token, self.get_cookie(token.token, expires_at)

    def throttle_login_attempts(self, email, ip):
        rows = self.session.execute(throttle_login_sql, {
            'email': email,
            'login_attempt_ip': ip,
            'now': self.now or datetime.utcnow(),
            'period': self.login_attempt_period
        })

        result = rows.fetchone()

        if all(col == None for col in result):
            return

        if result.global_attempt_count >= self.max_global_login_attempts or \
           result.ip_attempt_count >= self.max_login_attempts_per_ip or \
           result.ip_block_attempt_count >= self.max_login_attempts_per_ip_block or \
           result.email_ip_attempt_count >= self.max_login_attempts_per_email_ip or \
           result.email_network_attempt_count >= self.max_login_attempts_per_email_network:
           abort(401, errors=['Too Many Login Attempts'])

    def fail_login_attempt(self, email, ip):
        log_entry = self.auth_log_entry_model(
            type='failed_login_attempt',
            email=email,
            ip=ip,
            timestamp=self.now or datetime.utcnow(),
            user_agent=request.user_agent.string)
        self.session.add(log_entry)
        self.session.commit()

        abort(401, errors=['Not Authorized'])

    def log_login_success(self, user, ip):
        log_entry = self.auth_log_entry_model(
            type='login',
            email=user.email,
            user_id=user.id,
            ip=ip,
            timestamp=self.now or datetime.utcnow(),
            user_agent=request.user_agent.string)
        self.session.add(log_entry)
        self.session.commit()

    def enforce_max_sessions(self, user):
        session_count = self.session.query(func.count(self.token_model.id))\
            .filter(self.token_model.type == 'session',
                    self.token_model.user_id == user.id,
                    self.token_model.revoked_at == None,
                    self.token_model.expires_at > func.now())\
            .scalar()

        if session_count >= self.max_active_sessions_per_user:
            abort(401, errors=['Maximum number of user sessions reached.'])

    def post(self):
        raw_body = request.json
        session_load = session_schema.load(raw_body or {})

        if session_load.errors:
            abort(400, errors=session_load.errors)

        session = session_load.data
        email = session['email'].lower() ## force email to be case insensitive

        ip = get_ip(self.number_of_proxies)

        self.throttle_login_attempts(email, ip)

        user = self.session.query(self.User)\
                    .filter(self.User.email == email)\
                    .first()

        if not user:
            self.fail_login_attempt(email, ip)

        password_matches = user.verify_password(session['password'])
        if not password_matches:
            self.fail_login_attempt(email, ip)

        self.enforce_max_sessions(user)

        token, cookie = self.session_token(user, ip)

        self.log_login_success(user, ip)

        return None, 201, {'Set-Cookie': cookie}

    @login_required
    def get(self):
        return None, 204

    @login_required
    def delete(self):
        token = current_user.token
        token.revoked_at = datetime.utcnow()
        self.session.commit()

        cookie = self.get_cookie('deleted', 'Thu, 01 Jan 1970 00:00:00 GMT')

        return None, 204, {'Set-Cookie': cookie}

class BaseAuth(object):
    def extract_token_str(self, request):
        token_str = None

        authorization_header = request.headers.get('Authorization')
        if authorization_header:
            token_str = authorization_header.replace('Bearer ', '', 1)
        elif self.cookie_name in request.cookies:
            token_str = request.cookies[self.cookie_name]

        return token_str

    def init_app(self, app):
        self.login_manager.init_app(app)
        setattr(app, 'auth', self)

class AuthStandalone(BaseAuth):
    def __init__(self,
                 app=None,
                 session=None,
                 base_model=None,
                 user_model=None,
                 token_model=None,
                 token_secret=None,
                 auth_log_entry_model=None,
                 session_resource=None,
                 cookie_name='session',
                 cookie_domain=None,
                 cookie_path=None,
                 secure_cookie=False,
                 session_timeout=timedelta(hours=12),
                 number_of_proxies=0,
                 now=None,
                 login_attempt_period=900,
                 max_global_login_attempts=500,
                 max_login_attempts_per_ip=100,
                 max_login_attempts_per_ip_block=200,
                 max_login_attempts_per_email=5):
        self.user_model = user_model
        self.session = session

        self.cookie_name = cookie_name

        self.login_manager = LoginManager()
        self.login_manager.request_loader(self.load_user_from_request)

        if app:
            self.init_app(app)

        if base_model and not token_model:
            token_secret = token_secret or os.getenv('TOKEN_SECRET', None)
            if not token_secret:
                raise Exception('`token_secret` required if `token_model` is not passed')

            self.token_model = type('Token', (TokenMixin, base_model,), {
                'fernet': Fernet(token_secret)
            })
        else:
            self.token_model = token_model

        if base_model and not auth_log_entry_model:
            self.auth_log_entry_model = type('AuthLogEntry', (AuthLogEntryMixin, base_model,), {})
        else:
            self.auth_log_entry_model = auth_log_entry_model

        if session_resource:
            self.session_resource = session_resource
        else:
            self.session_resource = type('LocalSessionResource', (SessionResource,), {
                'User': self.user_model,
                'token_model': self.token_model,
                'session': self.session,
                'cookie_name': self.cookie_name,
                'cookie_domain': cookie_domain,
                'cookie_path': cookie_path,
                'secure_cookie': secure_cookie,
                'session_timeout': session_timeout,
                'number_of_proxies': number_of_proxies,
                'auth_log_entry_model': self.auth_log_entry_model,
                'now': now,
                'login_attempt_period': login_attempt_period,
                'max_global_login_attempts': max_global_login_attempts,
                'max_login_attempts_per_ip': max_login_attempts_per_ip,
                'max_login_attempts_per_ip_block': max_login_attempts_per_ip_block,
                'max_login_attempts_per_email': max_login_attempts_per_email
            })

    def load_user_from_request(self, request):
        token_str = self.extract_token_str(request)

        token = self.token_model.verify_token(self.session, token_str)

        ## TODO: check scope?
        ## TODO: make sure token type is session

        if token == None:
            return None

        user = self.session.query(self.user_model).get(token.user_id)

        if user == None:
            return None

        setattr(user, 'token', token)

        return user

class AuthServiceClient(BaseAuth):
    def __init__(self,
                 app=None,
                 token_secret=None,
                 cookie_name='session',
                 cookie_domain=None,
                 cookie_path=None,
                 secure_cookie=False,
                 session_timeout=timedelta(hours=12),
                 number_of_proxies=0):
        self.cookie_name = cookie_name

        self.login_manager = LoginManager()
        self.login_manager.request_loader(self.load_user_from_request)

        self.token_fernet = Fernet(token_secret)

        if app:
            self.init_app(app)

    def load_user_from_request(self, request):
        token_str = self.extract_token_str(request)

        data = verify_token_fernet(self.token_fernet, token_str)

        ## TODO: check scope?
        ## TODO: make sure token type is session

        if data == None:
            return None

        try:
            user, token = self.get_user_token(token_str)
        except Exception as e:
            if isinstance(e, NotImplementedError):
                raise e
            return None

        setattr(user, 'token', token)

        return user

    def get_user_token(self, token_str):
        raise NotImplementedError()
