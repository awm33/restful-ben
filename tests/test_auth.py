import re
from datetime import datetime, timedelta

from restful_ben.test_utils import json_call, login, dict_contains, iso_regex

from app_fixtures import app, db

def test_login(app):
    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='foo')

    assert response.status_code == 201
    assert 'csrf_token' in response.json
    assert len(response.json['csrf_token']) > 64
    assert 'Set-Cookie' in response.headers

    cookie_regex = r'session=[^;]+;\sExpires=[A-Za-z]{3},\s[0-9]{2}\s[A-Za-z]{3}\s[0-9]{4}\s[0-9]{2}:[0-9]{2}:[0-9]{2}\sGMT;\sHttpOnly'

    matches = re.match(cookie_regex, response.headers['Set-Cookie'])
    assert matches != None

    with app.app_context():
        log_entry = db.session.query(app.auth.auth_log_entry_model).first()
        assert log_entry.type == 'login'
        assert log_entry.email == 'amadonna@example.com'
        assert log_entry.user_id == 1
        assert log_entry.ip == '127.0.0.1'
        assert isinstance(log_entry.timestamp, datetime)
        assert log_entry.user_agent == 'werkzeug/0.12.2'

def test_login_fail(app):
    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='bar')
    assert response.status_code == 401

    response = json_call(test_client.post, '/session', email='notauser@example.com', password='foo')
    assert response.status_code == 401

    with app.app_context():
        log_entry = db.session.query(app.auth.auth_log_entry_model).first()
        assert log_entry.type == 'failed_login_attempt'
        assert log_entry.email == 'amadonna@example.com'
        assert log_entry.user_id == None
        assert log_entry.ip == '127.0.0.1'
        assert isinstance(log_entry.timestamp, datetime)
        assert log_entry.user_agent == 'werkzeug/0.12.2'

def test_global_login_attempts(app):
    auth_log_entry_model = app.auth.auth_log_entry_model
    with app.app_context():
        for i in range(0, 500):
            db.session.add(auth_log_entry_model(
                type='failed_login_attempt',
                email='foo@example.com',
                ip='76.68.48.234',
                timestamp=datetime.utcnow(),
                user_agent='Curl or something'))
        db.session.commit()

    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='foo')
    assert response.status_code == 401
    assert response.json['errors'][0] == 'Too Many Login Attempts'

def test_ip_login_attempts(app):
    auth_log_entry_model = app.auth.auth_log_entry_model
    with app.app_context():
        for i in range(0, 100):
            db.session.add(auth_log_entry_model(
                type='failed_login_attempt',
                email='foo@example.com',
                ip='127.0.0.1',
                timestamp=datetime.utcnow(),
                user_agent='Curl or something'))
        db.session.commit()

    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='foo')
    assert response.status_code == 401
    assert response.json['errors'][0] == 'Too Many Login Attempts'

def test_ip_block_login_attempts(app):
    auth_log_entry_model = app.auth.auth_log_entry_model
    with app.app_context():
        for i in range(0, 200):
            db.session.add(auth_log_entry_model(
                type='failed_login_attempt',
                email='foo@example.com',
                ip='127.0.0.23',
                timestamp=datetime.utcnow(),
                user_agent='Curl or something'))
        db.session.commit()

    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='foo')
    assert response.status_code == 401
    assert response.json['errors'][0] == 'Too Many Login Attempts'

def test_email_ip_login_attempts(app):
    auth_log_entry_model = app.auth.auth_log_entry_model
    with app.app_context():
        for i in range(0, 5):
            db.session.add(auth_log_entry_model(
                type='failed_login_attempt',
                email='amadonna@example.com',
                ip='127.0.0.1',
                timestamp=datetime.utcnow(),
                user_agent='Curl or something'))
        db.session.commit()

    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='foo')
    assert response.status_code == 401
    assert response.json['errors'][0] == 'Too Many Login Attempts'

def test_email_ip_block_login_attempts(app):
    auth_log_entry_model = app.auth.auth_log_entry_model
    with app.app_context():
        for i in range(0, 10):
            db.session.add(auth_log_entry_model(
                type='failed_login_attempt',
                email='amadonna@example.com',
                ip='127.0.0.23',
                timestamp=datetime.utcnow(),
                user_agent='Curl or something'))
        db.session.commit()

    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='foo')
    assert response.status_code == 401
    assert response.json['errors'][0] == 'Too Many Login Attempts'

def test_max_sessions(app):
    token_model = app.auth.token_model
    with app.app_context():
        for i in range(0, 10):
            db.session.add(token_model(
                type='session',
                user_id=1,
                expires_at=datetime.utcnow() + timedelta(hours=12),
                ip='127.0.0.1',
                user_agent='Curl or something'))
        db.session.commit()

    test_client = app.test_client()

    response = json_call(test_client.post, '/session', email='amadonna@example.com', password='foo')
    assert response.status_code == 401
    assert response.json['errors'][0] == 'Maximum number of user sessions reached.'

def test_get_session(app):
    test_client = app.test_client()
    login(test_client)

    response = test_client.get('/session')
    assert response.status_code == 204

    test_client = app.test_client()
    response = test_client.get('/session')
    assert response.status_code == 401

def test_logout(app):
    test_client = app.test_client()
    login(test_client)

    response = test_client.get('/session')
    assert response.status_code == 204

    response = test_client.delete('/session')
    assert response.status_code == 204
    assert 'Set-Cookie' in response.headers
    assert response.headers['Set-Cookie'] == 'session=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly'

    with app.app_context():
        token = db.session.query(app.auth.token_model).one()

    assert isinstance(token.revoked_at, datetime)

    response = test_client.get('/session')
    assert response.status_code == 401

def test_requires_login(app):
    test_client = app.test_client()

    response = json_call(test_client.get, '/cats')
    assert response.status_code == 401

def test_csrf(app):
    test_client = app.test_client()
    csrf_token = login(test_client)

    ## POST

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby',
        'age': 7
    })
    assert response.status_code == 401

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby',
        'age': 7
    }, headers={'X-CSRF': csrf_token})
    assert response.status_code == 201
    assert dict_contains(response.json, {
        'id': 4,
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby',
        'age': 7,
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    ## PUT

    response = json_call(test_client.get, '/cats/2')
    assert response.status_code == 200

    cat = response.json
    cat['age'] = 3

    response = json_call(test_client.put, '/cats/2', cat)
    assert response.status_code == 401

    response = json_call(test_client.put, '/cats/2', cat, headers={'X-CSRF': csrf_token})
    assert response.status_code == 200
    assert dict_contains(response.json, {
        'id': 2,
        'name': 'Leo',
        'age': 3,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    ## DELETE

    response = test_client.delete('/cats/2')
    assert response.status_code == 401

    response = test_client.delete('/cats/2', headers={'X-CSRF': csrf_token})
    assert response.status_code == 204

    response = test_client.get('/cats/2')
    assert response.status_code == 404

def test_authorization(app):
    test_client = app.test_client()
    csrf_token = login(test_client, email='jdoe@example.com', password='icecream') ## normal role

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby',
        'age': 7
    }, headers={'X-CSRF': csrf_token})
    assert response.status_code == 403

    csrf_token = login(test_client, email='amadonna@example.com', password='foo') ## admin role

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby',
        'age': 7
    }, headers={'X-CSRF': csrf_token})
    assert response.status_code == 201
