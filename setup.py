#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages

setup(
    name='restful_ben',
    version='0.4.0',
    packages=find_packages(),
    install_requires=[
        'argon2-cffi==16.3.0',
        'cryptography==1.9',
        'Flask==0.12.2',
        'Flask-Login==0.4.0',
        'Flask-RESTful==0.3.6',
        'Flask-SQLAlchemy==2.2',
        'marshmallow==2.13.5',
        'marshmallow-sqlalchemy==0.13.1',
        'passlib==1.7.1',
        'psycopg2==2.7.1',
        'python-dateutil==2.6.0'
    ],
)
