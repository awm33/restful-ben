#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages

with open('README.md') as file:
    long_description = file.read()

setup(
    name='restful-ben',
    version='0.4.2',
    author='Andrew Madonna',
    description='A composable SQLAlchemy based RESTful API library.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/awm33/restful-ben',
    packages=find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    install_requires=[
        'argon2-cffi==16.3.0',
        'cryptography==2.3',
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
