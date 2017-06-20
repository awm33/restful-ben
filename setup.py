#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages

setup(
    name='restful_ben',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
        'Flask==0.12.2',
        'Flask-RESTful==0.3.6',
        'Flask-SQLAlchemy==2.2',
        'marshmallow==2.13.5',
        'marshmallow-sqlalchemy==0.13.1',
        'passlib==1.7.1'
    ],
)
