from functools import wraps
import os

import pytest
import flask
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema, field_for
from marshmallow import fields
from flask_restful import Api
from flask_login import UserMixin, login_required
from sqlalchemy import Column, String, Enum, Integer, DateTime, Boolean, func, MetaData, create_engine
from sqlalchemy.ext.declarative import declarative_base
from cryptography.fernet import Fernet

from restful_ben.auth import (
    UserAuthMixin,
    AuthStandalone,
    authorization,
    csrf_check
)
from restful_ben.resources import (
    RetrieveUpdateDeleteResource,
    QueryEngineMixin,
    CreateListResource
)

metadata = MetaData()
BaseModel = declarative_base(metadata=metadata)

class User(UserAuthMixin, UserMixin, BaseModel):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    active = Column(Boolean, nullable=False)
    email = Column(String)
    role = Column(Enum('normal','admin', name='user_roles'), nullable=False)
    created_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now())
    updated_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now(),
                        onupdate=func.now())

    @property
    def is_active(self):
        return self.active

    def __repr__(self):
        return '<User id: {} active: {} username: {} email: {}>'.format(self.id, \
                                                                        self.active, \
                                                                        self.username, \
                                                                        self.email)

db = SQLAlchemy(metadata=metadata, model_class=BaseModel)

## Users Resource

class UserSchema(ModelSchema):
    class Meta:
        model = User
        exclude = ['hashed_password']

    id = field_for(User, 'id', dump_only=True)
    password = fields.Str(load_only=True)
    created_at = field_for(User, 'created_at', dump_only=True)
    updated_at = field_for(User, 'updated_at', dump_only=True)

user_schema = UserSchema()
users_schema = UserSchema(many=True)

user_roles = {
    'normal': ['GET'],
    'admin': ['POST','GET','PUT','DELETE']
}

def user_authorization(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if hasattr(current_user, 'role'):
            role = current_user.role
        else:
            role = None
        
        if role and role in user_roles:
            if request.method in user_roles[role]:
                return func(*args, **kwargs)

        if role and 'instance_id' in kwargs and current_user.id == int(kwargs['instance_id']):
            return func(*args, **kwargs)

        abort(403)
    return wrapper

class UserResource(RetrieveUpdateDeleteResource):
    method_decorators = [csrf_check, user_authorization, login_required]

    single_schema = user_schema
    model = User
    session = db.session

class UserListResource(QueryEngineMixin, CreateListResource):
    method_decorators = [csrf_check, user_authorization, login_required]

    query_engine_exclude_fields = ['hashed_password', 'password']
    single_schema = user_schema
    many_schema = users_schema
    model = User
    session = db.session

## Test Resources

class Cat(BaseModel):
    __tablename__ = 'cats'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    breed = Column(String)
    age = Column(Integer)
    created_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now())
    updated_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now(),
                        onupdate=func.now())

    def __repr__(self):
        return '<Cat id: {} name: {} breed: {} age: {}>'.format(self.id, \
                                                                self.name, \
                                                                self.breed, \
                                                                self.age)

class CatSchema(ModelSchema):
    class Meta:
        model = Cat

    id = field_for(Cat, 'id', dump_only=True)
    created_at = field_for(Cat, 'created_at', dump_only=True)
    updated_at = field_for(Cat, 'updated_at', dump_only=True)

cat_schema = CatSchema()
cats_schema = CatSchema(many=True)

cat_authorization = authorization({
    'normal': ['GET'],
    'admin': ['POST','PUT','GET','DELETE']
})

class CatResource(RetrieveUpdateDeleteResource):
    method_decorators = [csrf_check, cat_authorization, login_required]
    single_schema = cat_schema
    model = Cat
    session = db.session

class CatListResource(QueryEngineMixin, CreateListResource):
    method_decorators = [csrf_check, cat_authorization, login_required]
    single_schema = cat_schema
    many_schema = cats_schema
    model = Cat
    session = db.session

## Test App

@pytest.fixture
def app():
    connection_string = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://localhost/restful_ben_test')

    app = flask.Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = connection_string

    db.init_app(app)
    api = Api(app)

    ## hack to prevent loading the Token model multiple times. Only an issue for tests
    token_model = None
    for cls in BaseModel._decl_class_registry.values():
        if hasattr(cls, '__name__') and cls.__name__ == 'Token':
            token_model = cls

    auth = AuthStandalone(
                app=app,
                session=db.session,
                base_model=BaseModel,
                token_model=token_model,
                user_model=User,
                token_secret=Fernet.generate_key(),
                csrf_secret=Fernet.generate_key())

    with app.app_context():
        db.create_all()

        ## seed users
        db.session.add(User(active=True, username='amadonna', password='foo', role='admin'))
        db.session.add(User(active=True, username='jdoe', password='icecream', role='normal'))
        db.session.add(User(active=True, username='kclarkson', password='icecream', role='normal'))
        db.session.add(User(active=True, username='whouston', password='icecream', role='admin'))
        db.session.commit()

        ## seed cats
        db.session.add(Cat(name='Ada', breed='Tabby', age=5))
        db.session.add(Cat(name='Leo', breed='Tabby', age=2))
        db.session.add(Cat(name='Wilhelmina', breed='Calico', age=4))
        db.session.commit()

        api.add_resource(UserListResource, '/users')
        api.add_resource(UserResource, '/users/<int:instance_id>')
        api.add_resource(auth.session_resource, '/session')
        api.add_resource(CatListResource, '/cats')
        api.add_resource(CatResource, '/cats/<int:instance_id>')

    yield app

    engine = create_engine(connection_string)
    BaseModel.metadata.drop_all(engine)

