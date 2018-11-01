from ._entity import Entity, flatten
from abc import abstractmethod
from boto3.dynamodb.conditions import Key, Attr, ConditionExpressionBuilder
from botocore.exceptions import ClientError
from decimal import Decimal
from functools import reduce
from operator import iand
import boto3
import datetime
import json

from ..utils.formatters import format_datetime
from ..utils.serialisable import json_serialise
from ..utils.exceptions import NoSuchEntityException, DuplicateEntityException, NoUpdatesException

_dynamodb_client = boto3.client('dynamodb')


class DynamodbEntity(Entity):
    _dynamodb_table_name = None

    def __init__(self, primary_key):
        super().__init__(primary_key)
        self._index = None

    @classmethod
    def get_many(cls, **kwargs):
        if len(kwargs) == 1:
            key, values = next(iter(kwargs.items()))
            if isinstance(values, list):
                if len(values) > 100:
                    raise Exception('Can only scan for maximum of 100 keys at once')
                keys = [{key: {'S': v}} for v in values]  # TODO this only supports string-type keys
            else:
                raise Exception('DynamodbEntity.fetch_many() must be called as fetch_many(key: [value, ...])')
        elif len(kwargs) > 1:
            raise Exception('DynamodbEntity can only be filtered on one property')
        else:
            raise Exception('Cannot scan whole table')

        res = _dynamodb_client.batch_get_item(RequestItems={cls._dynamodb_table_name: {'Keys': keys}})

        def _cast(field_type, value):
            return {
                'BOOL': lambda x: bool(x),
                'L': lambda x: list(x),
                'N': lambda x: float(x),
                'NULL': lambda x: None,
                'S': lambda x: x,
                'SS': lambda x: list(x),
            }[field_type](value)

        ret = []
        for row in res['Responses'][cls._dynamodb_table_name]:
            # Unpack the weird {'stringytype': {'S': 'Stringyvalue'}, 'numerictype': {'N': '42'}} response
            record = {attr_name: _cast(*list(v.items())[0]) for attr_name, v in row.items()}

            obj = cls(record[key])
            obj._hydrate(record)
            ret.append(obj.get())

        if len(res.get('UnprocessedKeys', [])) > 0:
            raise Exception(f"Unprocessed keys in get_many(): {res['UnprocessedKeys']}")

        return ret, None

    def _fetch(self):
        # And together all the elements of the primary key
        kcx = reduce(iand, [Key(k).eq(v) for k, v in self.primary_key.items()])
        res = self._query_dynamodb(kcx, index=self._index)

        if len(res) == 0:
            raise NoSuchEntityException()
        print(res[0])
        return res[0]

    def patch(self, body):
        """
        Update an item
        :param dict body:
        :return:
        """
        self.validate('PATCH', body)
        body = flatten(body)

        condition = reduce(iand, [Attr(k).exists() for k in self.primary_key.keys()])

        keys = self.get_fields(immutable=False, primary_key=False)
        upsert = self.DynamodbUpdate()
        for key in keys:
            if isinstance(self._fields[key]['type'], list):
                if key in body:
                    upsert.add(key, set(body[key]))
                if f'¬{key}' in body:
                    upsert.delete(key, set(body[f'¬{key}']).difference({'_empty'}))
                if f'@{key}' in body:
                    upsert.set(key, set(body[f'@{key}']).union({'_empty'}))
            elif self._fields[key]['type'] == 'number':
                if key in body:
                    upsert.set(key, Decimal(str(body[key])))
            elif key in body:
                upsert.set(key, body[key])

        try:
            return self._update_dynamodb(upsert, condition)
        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise DuplicateEntityException()
            else:
                print(str(e))
                raise

    def create(self, body):
        """
        Create
        :param dict body:
        :return:
        """
        self.validate('PUT', body)
        body = flatten(body)

        k = list(self.primary_key.keys())[0]
        condition = Attr(k).not_exists()
        body['created_date'] = format_datetime(datetime.datetime.now())

        keys = self.get_fields(immutable=None, primary_key=False)
        upsert = self.DynamodbUpdate()
        for key in keys:
            if isinstance(self._fields[key]['type'], list):
                if key in body:
                    upsert.set(key, set(body[key]).union({'_empty'}))
            elif self._fields[key]['type'] == 'number':
                if key in body:
                    upsert.set(key, Decimal(str(body[key])))
            elif key in body:
                upsert.set(key, body[key])

        try:
            self._update_dynamodb(upsert, condition)
        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise DuplicateEntityException()
            else:
                print(str(e))
                raise

        return self.primary_key

    def delete(self):
        self._get_dynamodb_resource().delete_item(Key=self.primary_key)

    @classmethod
    def _get_dynamodb_resource(cls):
        return boto3.resource('dynamodb').Table(cls._dynamodb_table_name)

    def _query_dynamodb(self, key_condition_expression, limit=10000, scan_index_forward=True, exclusive_start_key=None, index=None):
        args = {
            'Select': 'ALL_ATTRIBUTES',
            'Limit': limit,
            'KeyConditionExpression': key_condition_expression,
            'ScanIndexForward': scan_index_forward,
        }
        if exclusive_start_key is not None:
            args['ExclusiveStartKey'] = exclusive_start_key
        if index is not None:
            args['IndexName'] = index

        ret = self._get_dynamodb_resource().query(**args)

        if 'LastEvaluatedKey' in ret:
            # There are more records to be scanned
            return ret['Items'] + self._query_dynamodb(key_condition_expression, limit, scan_index_forward, ret['LastEvaluatedKey'])
        else:
            # No more items
            return ret['Items']

    def _update_dynamodb(self, upsert, condition_expression):
            print(json.dumps({
                'Key': self.primary_key,
                'UpdateExpression': upsert.update_expression,
                'ExpressionAttributeNames': upsert.parameter_names,
                'ExpressionAttributeValues': upsert.parameter_values,
                'ConditionExpression': ConditionExpressionBuilder().build_expression(condition_expression, False),
            }, default=json_serialise))

            if len(upsert.parameter_names) == 0:
                raise NoUpdatesException()

            # Update updated_date, if we're updating anything else
            upsert.set('updated_date', format_datetime(datetime.datetime.now()))

            self._get_dynamodb_resource().update_item(
                Key=self.primary_key,
                UpdateExpression=upsert.update_expression,
                ExpressionAttributeNames=upsert.parameter_names,
                ExpressionAttributeValues=upsert.parameter_values,
                ConditionExpression=condition_expression
            )

            return self.get()

    @staticmethod
    def _print_condition_expression(expression, is_key_condition):
        print(ConditionExpressionBuilder().build_expression(expression, is_key_condition))

    class DynamodbUpdate:
        def __init__(self):
            self._add = set([])
            self._set = set([])
            self._delete = set([])
            self._parameter_names = []
            self._parameter_values = {}
            self._parameter_count = 0

        def set(self, field, value):
            key = self._register_parameter_name(field)
            if key is not None:
                self._set.add(f'#{key} = :{key}')
                self._parameter_values[f':{key}'] = value

        def add(self, field, value):
            key = self._register_parameter_name(field)
            if key is not None:
                self._add.add(f'#{key} :{key}')
                value = set(value) if isinstance(value, list) else value
                self._parameter_values[f':{key}'] = value

        def delete(self, field, value):
            key = self._register_parameter_name(field)
            if key is not None:
                self._delete.add(f'#{key} :{key}')
                self._parameter_values[f':{key}'] = value

        @property
        def update_expression(self):
            set_str = 'SET {}'.format(', '.join(self._set)) if len(self._set) else ''
            add_str = 'ADD {}'.format(', '.join(self._add)) if len(self._add) else ''
            del_str = 'DELETE {}'.format(', '.join(self._delete)) if len(self._delete) else ''
            return f'{set_str} {add_str} {del_str}'

        @property
        def parameter_names(self):
            return {f'#p{i}': n for i, n in enumerate(self._parameter_names)}

        @property
        def parameter_values(self):
            return self._parameter_values

        def _register_parameter_name(self, parameter_name):
            if parameter_name in self._parameter_names:
                return None
            self._parameter_names.append(parameter_name)
            return 'p' + str(len(self._parameter_names) - 1)

        def __str__(self):
            return str({
                'update_expression': self.update_expression,
                'parameter_names': self.parameter_names,
                'parameter_values': self.parameter_values,
            })

