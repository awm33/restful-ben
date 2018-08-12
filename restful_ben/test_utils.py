import json
import re

iso_regex = re.compile('^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{6})?\+[0-9]{2}:[0-9]{2}$')
regex_type = type(iso_regex)

def json_call(fn, path, *args, **kwargs):
    data = None

    if len(args) > 0:
        data = args[0]
    elif 'headers' not in kwargs:
        data = kwargs
        kwargs = dict()

    if data and len(data.keys()) > 0:
        kwargs['data'] = json.dumps(data)
        kwargs['content_type'] = 'application/json'

    response = fn(path, **kwargs)
    if response.status_code != 204:
        response.json = json.loads(response.data.decode())
    return response

def dict_contains(dict1, dict2):
    for key in dict2:
        if key not in dict1:
            return False
        if isinstance(dict2[key], regex_type):
            if re.match(dict2[key], dict1[key]) == None:
                return False
        elif type(dict2[key]) == type:
            if type(dict1[key]) != dict2[key]:
                return False
        elif dict1[key] != dict2[key]:
            return False
    return True

def login(test_client, path='/session', email='amadonna@example.com', password='foo'):
    response = json_call(test_client.post, path, email=email, password=password)
    assert response.status_code == 201
