import math

from flask import request
from flask_restful import Resource, abort
from sqlalchemy.sql import func
from sqlalchemy.inspection import inspect

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

## TODO: nested quuerying aka querying associated models

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
        'ilike',
        'in_', # in
        'notin_', # not in
        'notlike', # not like
        'notilike', # not ilike
        'is',
        'isnot', # is not
        'startswith',
        'endswith',
        'is_distinct_from', # a IS DISTINCT FROM b
        'isnot_distinct_from', # a IS NOT DISTINCT FROM b
    ]

    alias_operations = {
        'lte': 'le',
        'gte': 'ge',
        'in': 'in_',
        'notin': 'notin_'
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
        for key, value in request.args.items():
            if key in self.reserved_keys:
                continue

            split_key = key.split('__')
            field_key = split_key[0]

            field = getattr(self.model, field_key, None)
            if field is None or field_key in self.query_engine_exclude_fields:
                abort(400, errors=['Field `{}` does not exist or is not available for query on {}'.format(field_key, self.model.__name__)])

            num_args = len(split_key)
            if num_args == 1:
                op = 'eq'
            elif num_args == 2:
                op = split_key[1]
            else:
                abort(400, errors=['Invalid filter argument `{}`'.format(key)])

            if hasattr(self, 'operator_overrides') and \
               field_key in self.operator_overrides and \
               op in self.operator_overrides[field_key]:
                filters.append(self.operator_overrides[field_key][op](value))
                continue

            if op in self.alias_operations:
                op = self.alias_operations[op]
            
            if op not in self.allowed_operations:
                abort(400, errors=['Operator `{}` not available on {}'.format(op, self.model.__name__)])
            
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
                    field = raw_order_field[1:]
                else:
                    order = 'asc'
                    field = raw_order_field

                if not hasattr(self.model, field):
                    abort(400, errors=['`{}` does not exist on {}'.format(field, self.model.__name__)])

                model_field = getattr(self.model, field)
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
        return self.single_schema.dump(instance).data

    def get(self):
        instances = self.session.query(self.model)
        return self.many_schema.dump(instances).data
