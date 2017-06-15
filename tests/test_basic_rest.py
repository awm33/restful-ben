import json
import re

from app_fixtures import app

def json_call(fn, path, *args, **kwargs):
    if len(args) > 0:
        data = args[0]
    else:
        data = kwargs
        kwargs = dict()

    if len(data.keys()) > 0:
        kwargs['data'] = json.dumps(data)
        kwargs['content_type'] = 'application/json'

    response = fn(path, **kwargs)
    response.json = json.loads(response.data.decode())
    return response

def dict_contains(dict1, dict2):
    for key in dict2:
        if key not in dict1:
            return False
        if isinstance(dict2[key], re._pattern_type):
            if re.match(dict2[key], dict1[key]) == None:
                return False
        elif dict1[key] != dict2[key]:
            return False
    return True

iso_regex = re.compile('^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+[0-9]{2}:[0-9]{2}$')

def login(test_client, username='amadonna', password='foo'):
    response = json_call(test_client.post, '/session', username=username, password=password)
    assert response.status_code == 200

def test_create(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'breed': 'Tabby',
        'age': 7
    })
    assert response.status_code == 200
    assert dict_contains(response.json, {
        'id': 4,
        'name': 'Dr. Kitty McMoewMoew',
        'breed': 'Tabby',
        'age': 7,
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_list(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert len(response.json['data']) == 3
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][2], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'breed': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_filter_by_breed(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?breed=Tabby')
    assert response.status_code == 200
    assert response.json['count'] == 2
    assert len(response.json['data']) == 2
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_order_by_breed(app):
    test_client = app.test_client()
    login(test_client)

    ## asc
    response = json_call(test_client.get, '/cats?$order_by=breed')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert len(response.json['data']) == 3
    assert dict_contains(response.json['data'][0], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'breed': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][2], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    ## desc
    response = json_call(test_client.get, '/cats?$order_by=-breed')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert len(response.json['data']) == 3
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][2], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'breed': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_pagination(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?$page_size=1')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert len(response.json['data']) == 1
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    response = json_call(test_client.get, '/cats?$page=2&$page_size=1')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert len(response.json['data']) == 1
    assert dict_contains(response.json['data'][0], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    response = json_call(test_client.get, '/cats?$page=3&$page_size=1')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert len(response.json['data']) == 1
    assert dict_contains(response.json['data'][0], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'breed': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_retrieve(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats/2')
    assert response.status_code == 200
    assert dict_contains(response.json, {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'breed': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
