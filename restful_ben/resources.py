import math

from flask import request
from flask_restful import Resource, abort
from sqlalchemy.sql import func
from sqlalchemy.inspection import inspect
from sqlalchemy.dialects.postgresql import JSONB

class BaseResource(Resource):
    def dispatch(self, *args, **kwargs):
        if hasattr(self, 'methods'):
            method = request.method
            if method not in self.methods and method not in ['HEAD','OPTIONS']:
                raise Exception('Unimplemented method %r' % request.method)
        return super(BaseResource, self).dispatch(*args, **kwargs)

    def get_pk(self):
        if hasattr(self, 'primary_key'):
            return self.primary_key
        return inspect(self.model).primary_key[0] ## assumes not a composite key

class RetrieveUpdateDeleteResource(BaseResource):
    def get(self, instance_id):
        pk = self.get_pk()

        instance = self.session.query(self.model).filter(pk == instance_id).one_or_none()
        if not instance:
            abort(404, errors=['{} {} not found'.format(self.model.__name__, instance_id)])
        return self.single_schema.dump(instance).data

    def put(self, instance_id):
        pk = self.get_pk()
        raw_body = request.json

        instance = self.session.query(self.model).filter(pk == instance_id).one_or_none()
        if not instance:
            abort(404, errors=['{} {} not found'.format(self.model.__name__, instance_id)])

        instance_load = self.single_schema.load(raw_body, session=self.session, instance=instance)

        if instance_load.errors:
            abort(400, errors=instance_load.errors)

        ## Update related models
        relationships = inspect(self.model).relationships
        for relationship in relationships.keys():
            if relationship in raw_body:
                relationship_instance = getattr(instance, relationship)
                if isinstance(relationship_instance, list):
                    fpk = relationships[relationship].mapper.primary_key[0].name
                    frelationships = relationships[relationship].mapper.relationships.keys()
                    class_ = relationships[relationship].mapper.class_
                    fpks_to_keep = set()
                    newly_added = set()
                    for item in raw_body[relationship]:
                        if fpk not in item:
                            new_instance = class_(**item)
                            relationship_instance.append(new_instance)
                            newly_added.add(new_instance)
                        else:
                            fpks_to_keep.add(item[fpk])
                            item_instance = None
                            for k in relationship_instance:
                                if getattr(k, fpk) == item[fpk]:
                                    item_instance = k
                                    break
                            if not item_instance:
                                raise Exception('{}: {} {} not found'.format(class_.__name__, fpk, item[fpk]))
                            for key, value in item.items():
                                if key not in frelationships:
                                    setattr(item_instance, key, value)

                    for item in relationship_instance:
                        if item not in newly_added and getattr(item, fpk) not in fpks_to_keep:
                            relationship_instance.remove(item)

        self.session.commit()
        self.session.refresh(instance)
        return self.single_schema.dump(instance).data

    def delete(self, instance_id):
        pk = self.get_pk()

        instance = self.session.query(self.model).filter(pk == instance_id).one_or_none()
        if not instance:
            abort(404, errors=['{} {} not found'.format(self.model.__name__, instance_id)])
        self.session.delete(instance)
        self.session.commit()
        return None, 204

## TODO: nested querying aka querying associated models

class QueryEngineMixin(object):
    page_key = '$page'
    page_size_key = '$page_size'
    default_page_size = 100

    field_selection_key = '$fields'
    order_by_key = '$order_by'

    query_engine_exclude_fields = []

    allowed_operations = [
        'eq', # =
        'ne', # !=
        'lt', # <
        'le', # <=
        'gt', # >
        'ge', # >=
        'contains',
        'like',
        'notlike', # not like
        'ilike',
        'notilike', # not ilike
        'startswith',
        'endswith',
        'in_', # in
        'notin_', # not in
        'is_',
        'isnot' # is not
    ]

    alias_operations = {
        'lte': 'le',
        'gte': 'ge',
        'in': 'in_',
        'notin': 'notin_',
        'is': 'is_'
    }

    @property
    def reserved_keys(self):
        return [
            self.page_key,
            self.page_size_key,
            self.field_selection_key,
            self.order_by_key
        ]

    def get_filters(self):
        filters = []
        for key in request.args.keys():
            if key in self.reserved_keys:
                continue

            path = key.split('__')
            field_key = path[0]

            field = getattr(self.model, field_key, None)
            if field is None or field_key in self.query_engine_exclude_fields:
                abort(400, errors=['Field `{}` does not exist or is not available for query on {}'.format(field_key, self.model.__name__)])

            if len(path) > 1 and \
                (path[-1] in self.allowed_operations or path[-1] in self.alias_operations):
                op = path[-1]
                path = path[:-1]
            else:
                op = 'eq'

            if isinstance(field.type, JSONB) and len(path) > 1:
                field = field[path[1:]].astext

            if hasattr(self, 'operator_overrides') and \
               field_key in self.operator_overrides and \
               op in self.operator_overrides[field_key]:
                value = request.args.get(key)
                filters.append(self.operator_overrides[field_key][op](value))
                continue

            if op in self.alias_operations:
                op = self.alias_operations[op]
            
            if op not in self.allowed_operations:
                abort(400, errors=['Operator `{}` not available on {}'.format(op, self.model.__name__)])

            if op == 'in_' or op == 'notin_':
                value = request.args.getlist(key)
                filters.append(getattr(field, op)(value))
            elif op == 'is_' or op == 'isnot':
                value = request.args.get(key)
                value_lower = value.lower()
                if value_lower == 'null' or value_lower == 'none':
                    value = None
                elif value_lower == 'true':
                    value = True
                elif value_lower == 'false':
                    value = False
                filters.append(getattr(field, op)(value))
            else:
                value = request.args.get(key)
                field_op = list(filter(
                    lambda e: hasattr(field, e % op),
                    ['%s', '%s_', '__%s__']
                ))[0] % op

                filters.append(getattr(field, field_op)(value))
        return filters

    def get_pagination(self):
        raw_page = request.args.get(self.page_key)
        raw_page_size = request.args.get(self.page_size_key)
        
        if raw_page is None:
            page = 1
        else:
            try:
                page = int(raw_page)
                assert(page > 0)
            except:
                abort(400, errors=['`{}` is not a postive integer'.format(self.page_key)])

        if raw_page_size is None:
            page_size = self.default_page_size
        else:
            try:
                page_size = int(raw_page_size)
                assert(page_size >= 0)
            except:
                abort(400, errors=['`{}` must be an integer greater than or equal to 0'.format(self.page_size_key)])

        offset = (page - 1) * page_size

        return offset, page_size, page

    def get_ordering(self):
        raw_ordering = request.args.get(self.order_by_key)
        ordering = []

        if raw_ordering is not None:
            for raw_order_field in raw_ordering.split(','):
                if raw_order_field[0:1] == '-':
                    order = 'desc'
                    raw_path = raw_order_field[1:]
                else:
                    order = 'asc'
                    raw_path = raw_order_field

                path = raw_path.split('__')
                field = path[0]

                if not hasattr(self.model, field):
                    abort(400, errors=['`{}` does not exist on {}'.format(field, self.model.__name__)])

                model_field = getattr(self.model, field)
                if isinstance(model_field.type, JSONB) and len(path) > 1:
                    model_field = model_field[path[1:]].astext

                if order == 'desc':
                    ordering.append(model_field.desc())
                else:
                    ordering.append(model_field)
        else:
            ordering.append(self.get_pk())

        return ordering

    def get_field_selection(self):
        raw_fields = request.args.get(self.field_selection_key)

        if raw_fields is None:
            return [self.model]

        fields = []
        for raw_field in raw_fields.split(','):
            if not hasattr(self.model, raw_field):
                abort(400, errors=['`{}` does not exist on {}'.format(raw_field, self.model.__name__)])
            fields.append(getattr(self.model, raw_field))
        return fields

    def generate_query(self, offset, limit):
        fields = self.get_field_selection()
        filters = self.get_filters()
        ordering = self.get_ordering()

        return self.session.query(*fields)\
        .filter(*filters)\
        .order_by(*ordering)\
        .offset(offset)\
        .limit(limit)

    def get_query_count(self, query):
        count_q = query.statement.with_only_columns([func.count()])\
                    .offset(None)\
                    .limit(None)\
                    .order_by(None)
        return query.session.execute(count_q).scalar()

    def get(self):
        offset, limit, page = self.get_pagination()
        instances = self.generate_query(offset, limit)
        count = self.get_query_count(instances)
        return {
            'data': self.many_schema.dump(instances).data,
            'count': count,
            'page': page,
            'total_pages': math.ceil(count / limit)
        }

class CreateListResource(BaseResource):
    def post(self):
        raw_body = request.json
        instance_load = self.single_schema.load(raw_body, session=self.session)

        if instance_load.errors:
            abort(400, errors=instance_load.errors)

        instance = instance_load.data

        self.session.add(instance)
        self.session.commit()
        self.session.refresh(instance)
        return self.single_schema.dump(instance).data, 201

    def get(self):
        instances = self.session.query(self.model)
        return self.many_schema.dump(instances).data
