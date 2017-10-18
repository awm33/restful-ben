from app_fixtures import app
from restful_ben.test_utils import json_call, login, dict_contains, iso_regex

def test_equality(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?pattern=Tabby')
    assert response.status_code == 200
    assert response.json['count'] == 2
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 2

    response = json_call(test_client.get, '/cats?pattern__ne=Tabby')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Wilhelmina'

def test_greater_less_than(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?pattern=Tabby&age__gt=2')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Ada'

    response = json_call(test_client.get, '/cats?pattern=Tabby&age__gte=2')
    assert response.status_code == 200
    assert response.json['count'] == 2
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 2

    response = json_call(test_client.get, '/cats?pattern=Tabby&age__lte=2')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Leo'

    response = json_call(test_client.get, '/cats?age__lt=3')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Leo'

def test_string_search_operators(app):
    test_client = app.test_client()
    login(test_client)

    ## contains
    response = json_call(test_client.get, '/users?email__contains=houston')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['email'] == 'whouston@example.com'


    ## like
    response = json_call(test_client.get, '/users?email__like=%%houston%%')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['email'] == 'whouston@example.com'

    ## like is case sensitive
    response = json_call(test_client.get, '/cats?name__like=%%wilhelmina%%')
    assert response.status_code == 200
    assert response.json['count'] == 0
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 0
    assert len(response.json['data']) == 0

    ## notlike
    response = json_call(test_client.get, '/users?email__notlike=%%houston%%')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3

    ## ilike
    response = json_call(test_client.get, '/cats?name__ilike=%%wilhelmina%%')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Wilhelmina'

    ## notilike
    response = json_call(test_client.get, '/cats?name__notilike=%%wilhelmina%%')
    assert response.status_code == 200
    assert response.json['count'] == 2
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 2

    ## startswith
    response = json_call(test_client.get, '/cats?name__startswith=Wil')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Wilhelmina'

    ## endswith
    response = json_call(test_client.get, '/cats?name__endswith=da')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Ada'

def test_in_operator(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?name__in=Ada&name__in=Leo')
    assert response.status_code == 200
    assert response.json['count'] == 2
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 2

    response = json_call(test_client.get, '/cats?name__notin=Ada&name__notin=Leo')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Wilhelmina'

def test_is_operator(app):
    test_client = app.test_client()
    login(test_client)

    ## setup

    response = json_call(test_client.post, '/cats', {
        'name': 'Dr. Kitty McMoewMoew',
        'pattern': 'Tabby'
    }, headers={'X-Requested-With': 'requests'})
    assert response.status_code == 201

    response = json_call(test_client.get, '/users/1')
    assert response.status_code == 200
    user = response.json
    user['active'] = False
    response = json_call(test_client.put, '/users/1', user, headers={'X-Requested-With': 'requests'})
    assert response.status_code == 200

    ## is null
    response = json_call(test_client.get, '/cats?age__is=null')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['name'] == 'Dr. Kitty McMoewMoew'

    ## isnot null
    response = json_call(test_client.get, '/cats?age__isnot=null')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3

    ## is true
    response = json_call(test_client.get, '/users?active__is=true')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3

    ## is false
    response = json_call(test_client.get, '/users?active__is=false')
    assert response.status_code == 200
    assert response.json['count'] == 1
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 1
    assert response.json['data'][0]['email'] == 'amadonna@example.com'
