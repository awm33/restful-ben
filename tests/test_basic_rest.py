from app_fixtures import app
from restful_ben.test_utils import json_call, login, dict_contains, iso_regex

def test_create(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby',
        'age': 7
    }, headers={'X-Requested-With': 'requests'})
    assert response.status_code == 201
    assert dict_contains(response.json, {
        'id': 4,
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby',
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
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][2], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'pattern': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_filter_by_pattern(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?pattern=Tabby')
    assert response.status_code == 200
    assert response.json['count'] == 2
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 2
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_order_by_pattern(app):
    test_client = app.test_client()
    login(test_client)

    ## asc
    response = json_call(test_client.get, '/cats?$order_by=pattern')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3
    assert dict_contains(response.json['data'][0], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'pattern': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][2], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    ## desc
    response = json_call(test_client.get, '/cats?$order_by=-pattern')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][1], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][2], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'pattern': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

def test_pagination(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?$page_size=1')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 3
    assert len(response.json['data']) == 1
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    response = json_call(test_client.get, '/cats?$page=2&$page_size=1')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 2
    assert response.json['total_pages'] == 3
    assert len(response.json['data']) == 1
    assert dict_contains(response.json['data'][0], {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    response = json_call(test_client.get, '/cats?$page=3&$page_size=1')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 3
    assert response.json['total_pages'] == 3
    assert len(response.json['data']) == 1
    assert dict_contains(response.json['data'][0], {
        'id': 3,
        'name': 'Wilhelmina',
        'age': 4,
        'pattern': 'Calico',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

## TODO: test foreign key field selection

def test_field_selection(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?$fields=name,pattern')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3
    assert response.json['data'][0] == {
        'name': 'Ada',
        'pattern': 'Tabby'
    }
    assert response.json['data'][1] == {
        'name': 'Leo',
        'pattern': 'Tabby'
    }
    assert response.json['data'][2] == {
        'name': 'Wilhelmina',
        'pattern': 'Calico'
    }

def test_retrieve(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats/2')
    assert response.status_code == 200
    assert dict_contains(response.json, {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    response = json_call(test_client.get, '/cats/1234')
    assert response.status_code == 404

## TODO: test updated associated models / fields

def test_update(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats/2')
    assert response.status_code == 200
    assert dict_contains(response.json, {
        'id': 2,
        'name': 'Leo',
        'age': 2,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })

    cat = response.json
    cat['age'] = 3
    previous_updated_at = cat['updated_at']

    response = json_call(test_client.put, '/cats/2', cat, headers={'X-Requested-With': 'requests'})
    assert response.status_code == 200
    assert dict_contains(response.json, {
        'id': 2,
        'name': 'Leo',
        'age': 3,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert response.json['updated_at'] > previous_updated_at

    response = json_call(test_client.put, '/cats/1234', {}, headers={'X-Requested-With': 'requests'})
    assert response.status_code == 404

def test_delete(app):
    test_client = app.test_client()
    login(test_client)

    response = test_client.delete('/cats/2', headers={'X-Requested-With': 'requests'})
    assert response.status_code == 204

    response = test_client.get('/cats/2')
    assert response.status_code == 404

    response = json_call(test_client.delete, '/cats/1234', {}, headers={'X-Requested-With': 'requests'})
    assert response.status_code == 404
