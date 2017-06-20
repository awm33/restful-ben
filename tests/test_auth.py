from app_fixtures import app
from utils import json_call, login, dict_contains, iso_regex

def test_login(app):
    test_client = app.test_client()

    response = json_call(test_client.post, '/session', username='amadonna', password='foo')
    assert response.status_code == 200
    assert 'csrf_token' in response.json
    assert len(response.json['csrf_token']) > 64

def test_get_session(app):
    test_client = app.test_client()
    login(test_client)

    response = test_client.get('/session')
    assert response.status_code == 204

def test_logout(app):
    test_client = app.test_client()
    login(test_client)

    response = test_client.get('/session')
    assert response.status_code == 204

    response = test_client.delete('/session')
    assert response.status_code == 204

    response = test_client.get('/session')
    assert response.status_code == 401

def test_csrf(app):
    test_client = app.test_client()
    csrf_token = login(test_client)

    ## POST

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'breed': 'Tabby',
        'age': 7
    })
    assert response.status_code == 401

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'breed': 'Tabby',
        'age': 7
    }, headers={'X-CSRF': csrf_token})
    assert response.status_code == 201
    assert dict_contains(response.json, {
        'id': 4,
        'name': 'Dr. Kitty McMoewMoew',
        'breed': 'Tabby',
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
        'breed': 'Tabby',
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
    csrf_token = login(test_client, username='jdoe', password='icecream') ## normal role

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'breed': 'Tabby',
        'age': 7
    }, headers={'X-CSRF': csrf_token})
    assert response.status_code == 403

    csrf_token = login(test_client, username='amadonna', password='foo') ## admin role

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'breed': 'Tabby',
        'age': 7
    }, headers={'X-CSRF': csrf_token})
    assert response.status_code == 201
