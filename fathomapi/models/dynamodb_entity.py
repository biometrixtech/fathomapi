from ._entity import Entity
from boto3.dynamodb.conditions import Key, Attr, ConditionExpressionBuilder
from botocore.exceptions import ClientError
from decimal import Decimal
from functools import reduce
from operator import iand, ior
import boto3
import datetime
import json
import time

from ..utils.formatters import format_datetime
from ..utils.serialisable import json_serialise
from ..utils.exceptions import NoSuchEntityException, DuplicateEntityException, NoUpdatesException

_dynamodb_client = boto3.client('dynamodb')


class DynamodbEntity(Entity):
    _dynamodb_table_name = None

    def __init__(self, primary_key):
        super().__init__(primary_key)
        self._index = None
        self._secondary_key = None

    @classmethod
    def _get_many(cls, index=None, **kwargs):

        def _unserialise_ddb(field_type, value):
            return {
                'BOOL': lambda x: bool(x),
                'L': lambda x: list(x),
                'N': lambda x: float(x),
                'NULL': lambda x: None,
                'S': lambda x: x,
                'SS': lambda x: list(x),
            }[field_type](value)

        if len(kwargs) == 1:
            field, values = next(iter(kwargs.items()))
            if isinstance(values, list):
                # Get many by primary key
                keys = [{field: {'S': v}} for v in values]
                for i in range(0, len(keys), 100):
                    res = _dynamodb_client.batch_get_item(RequestItems={cls._dynamodb_table_name: {'Keys': keys[i:i+100]}})
                    for row in res['Responses'][cls._dynamodb_table_name]:
                        # Unpack the weird {'stringytype': {'S': 'Stringyvalue'}, 'numerictype': {'N': '42'}} response
                        record = {attr_name: _unserialise_ddb(*list(v.items())[0]) for attr_name, v in row.items()}
                        ret = cls(record[field])
                        ret._hydrate(record)
                        yield ret
            else:
                # Get many range keys matching a partition key
                yield from cls._query_dynamodb(Key(field).eq(values), index=index)

        elif len(kwargs) > 1:
            raise NotImplementedError('DynamodbEntity can only be filtered on one property')

        else:
            raise NotImplementedError('Cannot scan whole table')

    def _fetch(self):
        # And together all the elements of the primary key
        if self._secondary_key is not None:
            kcx = reduce(iand, [Key(k).eq(v) for k, v in self._secondary_key.items()])
        else:
            kcx = reduce(iand, [Key(k).eq(v) for k, v in self.primary_key.items()])
        print(f'primary_key={self.primary_key}, secondary_key={self._secondary_key}, index={self._index}')
        res = self._query_dynamodb(kcx, index=self._index)

        if len(res) == 0:
            raise NoSuchEntityException()
        print(res[0])
        self._primary_key = {k: res[0][k] for k in self._primary_key.keys()}
        return res[0]

    def patch(self, body):
        """
        Update an item
        :param dict body:
        :return:
        """
        self.validate('PATCH', body)
        body = self.flatten(body)

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
        body = self.flatten(body)

        k = list(self.primary_key.keys())[0]
        condition = Attr(k).not_exists()
        body['created_date'] = format_datetime(datetime.datetime.now())

        keys = self.get_fields(immutable=None, primary_key=False)
        upsert = self.DynamodbUpdate()
        for key in keys:
            if isinstance(self._fields[key]['type'], list):
                if key in body:
                    upsert.set(key, set(body[key]).union({'_empty'}))
                else:
                    upsert.set(key, {'_empty'})
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

    @classmethod
    def _query_dynamodb(cls, key_condition_expression, limit=10000, scan_index_forward=True, index=None):
        return cls.IteratedCall(cls._get_dynamodb_resource().query, 'Items', 'ExclusiveStartKey')(
            Select='ALL_ATTRIBUTES',
            Limit=limit,
            KeyConditionExpression=key_condition_expression,
            ScanIndexForward=scan_index_forward,
            IndexName=index,
        )

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

    class IteratedCall:
        def __init__(self, method, results_key, pagination_key):
            self._method = method
            self._results_key = results_key
            self._pagination_key = pagination_key

            self._pagination_value = None
            self._exponential_backoff = 128

        def __call__(self, **kwargs):
            try:
                kwargs[self._pagination_key] = self._pagination_value
                kwargs = {k: v for k, v in kwargs.items() if v is not None}

                res = self._method(**kwargs)
                ret = res[self._results_key]
                self._exponential_backoff = 128

                if self._pagination_key in res:
                    # There are more records to be scanned
                    self._pagination_value = res[self._pagination_key]
                    ret += self(**kwargs)

                return res[self._results_key]

            except ClientError as e:
                # TODO only retry on throttle
                if self._exponential_backoff > 128 ** 1:
                    raise
                else:
                    time.sleep(self._exponential_backoff / 1000)
                    self._exponential_backoff *= 2
                    return self(**kwargs)
