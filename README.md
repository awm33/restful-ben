# RESTful Ben

Ben's had a nap, he's feeling RESTful and ready to go.

A libray to assist creating [SQLAlchemy](https://www.sqlalchemy.org/), [Flask](http://flask.pocoo.org/), and [flask-restful](https://flask-restful.readthedocs.io/en/0.3.5/) based APIs.

### Features

- RESTful resources
	- Generates POST, GET (individual and list), PUT, and DELETE endpoints based on a SQLAlchemy model and a [Marshmallow](https://marshmallow.readthedocs.io/en/latest/) schema.
	- Query engine
		- Field selection
		- Filtering
		- Sorting
		- Pagination
- Authentication
	- Username and password based sessions
	- CSRF
	- Session endpoint - login (POST) and logout (DELETE)
- Authorization
   - Basic role based authorization
   - Roles map to HTTP verbs (GET, POST, etc)

## Usage

### Basic API

Create a model
   
```py
class Cat(BaseModel):
    __tablename__ = 'cats'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    pattern = Column(String)
    age = Column(Integer)
    created_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now())
    updated_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now(),
                        onupdate=func.now())
```

Create a [Marshmallow](https://marshmallow.readthedocs.io/en/latest/) schema to map a model to a JSON representation. This uses [Marshmallow SQLAlchemy](https://marshmallow-sqlalchemy.readthedocs.io/en/latest/) to generate the schema automatically.

```py
class CatSchema(ModelSchema):
    class Meta:
        model = Cat

    id = field_for(Cat, 'id', dump_only=True)
    created_at = field_for(Cat, 'created_at', dump_only=True)
    updated_at = field_for(Cat, 'updated_at', dump_only=True)

cat_schema = CatSchema()
cats_schema = CatSchema(many=True)
```

Create a resource for single Cat access, eg `/cats/:id`

```py
class CatResource(RetrieveUpdateDeleteResource):
    single_schema = cat_schema
    model = Cat
    session = db.session
```

Create a resource for listing Cats, eg `/cats`.

```py
class CatListResource(QueryEngineMixin, CreateListResource):
    single_schema = cat_schema
    many_schema = cats_schema
    model = Cat
    session = db.session
```

Setup your flask app:

```py
import flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api

from .routes import CatListResource, CatResource

db = SQLAlchemy()

app = flask.Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'some db'

db.init_app(app)
api = Api(app)

with app.app_context():
    db.create_all()
    
    api.add_resource(CatListResource, '/cats')
    api.add_resource(CatResource, '/cats/<int:instance_id>')
```

### Query Engine

#### Filtering

To filter based on equality simple use the field name plus filter value for one or more fields, ex `/cats?pattern=Tabby`. Other operations are available by adding an operator at the end of the field name separated by two underscores, ex `/cats?pattern__contains=Tabby`.

Operators

| Operator | Description | Notes / Example |
| ------ | ------ | ------ |
| eq | Equals - default | `/cats?pattern=Tabby` or `/cats?pattern__eq=Tabby` |
| ne  | Not Equals (!=) | `/cats?pattern__ne=Tabby` |
| lt | Less Than (<) | |
| lte | Less Than or Equal To (<=) | |
| gt | Greater Than (>) | |
| gte | Greater Than or Equal To (>=) | |
| contains | Contains | |
| like | Like | |
| ilike | Case Insensitive Like | |
| notlike | Not Like ||
| notilike | Case Insensitive Not Like | |
| startswith | Starts With | |
| endswith | Ends With | |
| in | In | `/cats?name__in=Ada&name__in=Leo` |
| notin | Not In | `/cats?name__notin=Ada&name__notin=Leo` |
| is | IS - Helper for `null` and `true`/`false` | `/cats?age__is=null` or `/users?active__is=true` or `/users?active__is=false` |
| isnot | IS NOT - Helper for `null` and `true`/`false` | `/cats?age__isnot=null` |

#### Ordering

Use the `$order_by` query parameter to set ordering by one or more fields. Fields are separated by a comma (,) and are ascending by default. Add a minus to the beginning of the field to order by descending.

Examples

`/cats?$order_by=name`

`/cats?$order_by=pattern,-updated_at`

#### Field selection

Use the `$fields` query parameter to select a subset of fields. Fields are comma (,) separated.

Examples

`/cats?$fields=id`

`/cats?$fields=id,name`

#### Pagination

Use the `$page` and `$page_size` query parameters to paginate. `$page_size` is not required and is 100 by default.

Examples

`/cats?$page=2`

`/cats?$page=2&$page_size=10`
